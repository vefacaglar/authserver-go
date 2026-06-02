package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserStore struct{ db *gorm.DB }

func NewUserStore(db *gorm.DB) *UserStore { return &UserStore{db: db} }

func (s *UserStore) CreateUser(ctx context.Context, user *domain.User, password string) error {
	if user.ID == "" {
		return errors.New("user: empty id")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	user.PasswordHash = string(hash)
	ent := toUserEntity(user)
	err = s.db.WithContext(ctx).Create(ent).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) ||
			strings.Contains(err.Error(), "UNIQUE constraint failed") ||
			strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return fmt.Errorf("user %q: %w", user.ID, store.ErrDuplicate)
		}
		return err
	}
	return nil
}

func (s *UserStore) UpdateUser(ctx context.Context, user *domain.User) error {
	var existing userEntity
	if err := s.db.WithContext(ctx).Where("id = ?", user.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("user %q: %w", user.ID, store.ErrNotFound)
		}
		return err
	}
	ent := toUserEntity(user)
	ent.PasswordHash = existing.PasswordHash
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *UserStore) DeleteUser(ctx context.Context, userID string) error {
	tx := s.db.WithContext(ctx)
	if err := tx.Where("user_id = ?", userID).Delete(&userClaimEntity{}).Error; err != nil {
		return err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&userRoleEntity{}).Error; err != nil {
		return err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&userLoginEntity{}).Error; err != nil {
		return err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&userTokenEntity{}).Error; err != nil {
		return err
	}
	result := tx.Where("id = ?", userID).Delete(&userEntity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	return nil
}

func (s *UserStore) FindUserByID(ctx context.Context, userID string) (*domain.User, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *UserStore) FindUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("normalized_username = ?", strings.ToUpper(username)).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user %q: %w", username, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *UserStore) FindUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("normalized_email = ?", strings.ToUpper(email)).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user %q: %w", email, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *UserStore) GetPagedUsers(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.User], error) {
	req = req.Normalized()
	var count int64
	if err := s.db.WithContext(ctx).Model(&userEntity{}).Count(&count).Error; err != nil {
		return domain.PagedResult[domain.User]{}, err
	}
	var entities []userEntity
	offset := (req.Page - 1) * req.PageSize
	if err := s.db.WithContext(ctx).Offset(offset).Limit(req.PageSize).Find(&entities).Error; err != nil {
		return domain.PagedResult[domain.User]{}, err
	}
	items := make([]domain.User, len(entities))
	for i := range entities {
		items[i] = *entities[i].toDomain()
	}
	return domain.PagedResult[domain.User]{
		Items:      items,
		TotalCount: int(count),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *UserStore) SetPassword(ctx context.Context, userID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	result := s.db.WithContext(ctx).Model(&userEntity{}).Where("id = ?", userID).Update("password_hash", string(hash))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	return nil
}

func (s *UserStore) ValidateCredentials(ctx context.Context, username, password string) (*domain.UserInfo, error) {
	var ent userEntity
	where := "id = ? OR normalized_username = ? OR normalized_email = ?"
	if err := s.db.WithContext(ctx).Where(where, username, strings.ToUpper(username), strings.ToUpper(username)).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("user lookup: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(ent.PasswordHash), []byte(password)) != nil {
		return nil, nil
	}
	claims, err := s.loadClaims(ctx, ent.ID)
	if err != nil {
		return nil, err
	}
	claims["preferred_username"] = ent.Username
	if ent.Email != "" {
		claims["email"] = ent.Email
		claims["email_verified"] = ent.EmailConfirmed
	}
	if ent.PhoneNumber != "" {
		claims["phone_number"] = ent.PhoneNumber
		claims["phone_number_verified"] = ent.PhoneNumberConfirmed
	}
	return &domain.UserInfo{UserID: ent.ID, Claims: claims}, nil
}

func (s *UserStore) FindByID(ctx context.Context, userID string) (*domain.UserInfo, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
		}
		return nil, err
	}
	claims, err := s.loadClaims(ctx, ent.ID)
	if err != nil {
		return nil, err
	}
	claims["preferred_username"] = ent.Username
	if ent.Email != "" {
		claims["email"] = ent.Email
		claims["email_verified"] = ent.EmailConfirmed
	}
	if ent.PhoneNumber != "" {
		claims["phone_number"] = ent.PhoneNumber
		claims["phone_number_verified"] = ent.PhoneNumberConfirmed
	}
	return &domain.UserInfo{UserID: ent.ID, Claims: claims}, nil
}

func (s *UserStore) loadClaims(ctx context.Context, userID string) (map[string]any, error) {
	var claimEntities []userClaimEntity
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&claimEntities).Error; err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	for _, c := range claimEntities {
		claims[c.Type] = c.Value
	}
	return claims, nil
}

func (s *UserStore) GetUserClaims(ctx context.Context, userID string) ([]domain.UserClaim, error) {
	var entities []userClaimEntity
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&entities).Error; err != nil {
		return nil, err
	}
	result := make([]domain.UserClaim, len(entities))
	for i, e := range entities {
		result[i] = domain.UserClaim{Type: e.Type, Value: e.Value}
	}
	return result, nil
}

func (s *UserStore) AddUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error {
	for _, c := range claims {
		ent := userClaimEntity{UserID: userID, Type: c.Type, Value: c.Value}
		if err := s.db.WithContext(ctx).Create(&ent).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *UserStore) RemoveUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error {
	for _, c := range claims {
		if err := s.db.WithContext(ctx).Where("user_id = ? AND type = ? AND value = ?", userID, c.Type, c.Value).Delete(&userClaimEntity{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *UserStore) ReplaceUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error {
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&userClaimEntity{}).Error; err != nil {
		return err
	}
	return s.AddUserClaims(ctx, userID, claims)
}

func (s *UserStore) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	var roleIDs []userRoleEntity
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&roleIDs).Error; err != nil {
		return nil, err
	}
	if len(roleIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(roleIDs))
	for i, ur := range roleIDs {
		ids[i] = ur.RoleID
	}
	var roles []roleEntity
	if err := s.db.WithContext(ctx).Where("id IN ?", ids).Find(&roles).Error; err != nil {
		return nil, err
	}
	result := make([]string, len(roles))
	for i, r := range roles {
		result[i] = r.Name
	}
	return result, nil
}

func (s *UserStore) AddToRoles(ctx context.Context, userID string, roles []string) error {
	for _, roleName := range roles {
		var role roleEntity
		if err := s.db.WithContext(ctx).Where("normalized_name = ?", strings.ToUpper(roleName)).First(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("role %q: %w", roleName, store.ErrNotFound)
			}
			return err
		}
		ur := userRoleEntity{UserID: userID, RoleID: role.ID}
		if err := s.db.WithContext(ctx).Create(&ur).Error; err != nil {
			if !strings.Contains(err.Error(), "UNIQUE") && !strings.Contains(err.Error(), "duplicate") {
				return err
			}
		}
	}
	return nil
}

func (s *UserStore) RemoveFromRoles(ctx context.Context, userID string, roles []string) error {
	for _, roleName := range roles {
		var role roleEntity
		if err := s.db.WithContext(ctx).Where("normalized_name = ?", strings.ToUpper(roleName)).First(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return err
		}
		if err := s.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, role.ID).Delete(&userRoleEntity{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *UserStore) GetUsersInRole(ctx context.Context, role string) ([]string, error) {
	var roleEnt roleEntity
	if err := s.db.WithContext(ctx).Where("normalized_name = ?", strings.ToUpper(role)).First(&roleEnt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var userRoles []userRoleEntity
	if err := s.db.WithContext(ctx).Where("role_id = ?", roleEnt.ID).Find(&userRoles).Error; err != nil {
		return nil, err
	}
	result := make([]string, len(userRoles))
	for i, ur := range userRoles {
		result[i] = ur.UserID
	}
	return result, nil
}

func (s *UserStore) GetUserLogins(ctx context.Context, userID string) ([]domain.UserLogin, error) {
	var entities []userLoginEntity
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&entities).Error; err != nil {
		return nil, err
	}
	result := make([]domain.UserLogin, len(entities))
	for i, e := range entities {
		result[i] = *e.toDomain()
	}
	return result, nil
}

func (s *UserStore) AddLogin(ctx context.Context, login *domain.UserLogin) error {
	ent := toUserLoginEntity(login)
	return s.db.WithContext(ctx).Create(ent).Error
}

func (s *UserStore) RemoveLogin(ctx context.Context, userID, provider, key string) error {
	result := s.db.WithContext(ctx).Where("user_id = ? AND login_provider = ? AND provider_key = ?", userID, provider, key).Delete(&userLoginEntity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("login %s/%s: %w", provider, key, store.ErrNotFound)
	}
	return nil
}

func (s *UserStore) FindByLogin(ctx context.Context, provider, key string) (*domain.User, error) {
	var loginEnt userLoginEntity
	if err := s.db.WithContext(ctx).Where("login_provider = ? AND provider_key = ?", provider, key).First(&loginEnt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("login %s/%s: %w", provider, key, store.ErrNotFound)
		}
		return nil, err
	}
	var userEnt userEntity
	if err := s.db.WithContext(ctx).Where("id = ?", loginEnt.UserID).First(&userEnt).Error; err != nil {
		return nil, err
	}
	return userEnt.toDomain(), nil
}

func (s *UserStore) SetUserToken(ctx context.Context, token *domain.UserToken) error {
	ent := toUserTokenEntity(token)
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *UserStore) GetUserToken(ctx context.Context, userID, provider, name string) (*domain.UserToken, error) {
	var ent userTokenEntity
	if err := s.db.WithContext(ctx).Where("user_id = ? AND login_provider = ? AND name = ?", userID, provider, name).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("token: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *UserStore) RemoveUserToken(ctx context.Context, userID, provider, name string) error {
	result := s.db.WithContext(ctx).Where("user_id = ? AND login_provider = ? AND name = ?", userID, provider, name).Delete(&userTokenEntity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("token: %w", store.ErrNotFound)
	}
	return nil
}
