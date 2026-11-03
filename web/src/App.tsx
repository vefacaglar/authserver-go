import { Navigate, Route, Routes } from "react-router";
import { AuthProvider } from "./lib/auth";
import RequireAuth from "./components/RequireAuth";
import AdminLayout from "./layouts/AdminLayout";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Home from "./pages/Home";
import Profile from "./pages/Profile";
import Logout from "./pages/Logout";
import Dashboard from "./admin/Dashboard";
import Clients from "./admin/Clients";
import Scopes from "./admin/Scopes";
import Users from "./admin/Users";
import Roles from "./admin/Roles";
import Sessions from "./admin/Sessions";
import RefreshTokens from "./admin/RefreshTokens";
import Keys from "./admin/Keys";
import Audit from "./admin/Audit";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/logout" element={<Logout />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <Home />
            </RequireAuth>
          }
        />
        <Route
          path="/profile"
          element={
            <RequireAuth>
              <Profile />
            </RequireAuth>
          }
        />
        <Route path="/admin" element={<AdminLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="clients" element={<Clients />} />
          <Route path="scopes" element={<Scopes />} />
          <Route path="users" element={<Users />} />
          <Route path="roles" element={<Roles />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="refresh-tokens" element={<RefreshTokens />} />
          <Route path="keys" element={<Keys />} />
          <Route path="audit" element={<Audit />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
