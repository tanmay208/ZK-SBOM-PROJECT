"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { authService } from "@/api/services/authService";
import { useAuth } from "@/auth/AuthProvider";
import { ApiError } from "@/api/errors";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordInput } from "@/components/ui/password-input";
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from "@/components/ui/card";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import {
  ShieldCheck,
  AlertCircle,
  Loader2,
  ArrowLeft,
  UserPlus,
  CheckCircle2,
  Shield,
  ArrowRight,
} from "lucide-react";
import Link from "next/link";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface FormValidationErrors {
  username?: string;
  password?: string;
  confirmPassword?: string;
}

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<FormValidationErrors>({});
  const [success, setSuccess] = useState(false);
  const router = useRouter();
  const { status } = useAuth();

  // If already authenticated, redirect to dashboard workspace
  useEffect(() => {
    if (status === "authenticated") {
      router.push("/dashboard");
    }
  }, [status, router]);

  // Handle redirect timer upon successful registration
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => {
        router.push("/login");
      }, 2500);
      return () => clearTimeout(timer);
    }
  }, [success, router]);

  const validateForm = (): boolean => {
    const errors: FormValidationErrors = {};
    const trimmedUser = username.trim();

    if (!trimmedUser) {
      errors.username = "Username is required";
    } else if (trimmedUser.length < 3) {
      errors.username = "Username must be at least 3 characters long";
    }

    if (!password) {
      errors.password = "Password is required";
    } else if (password.length < 8) {
      errors.password = "Password must be at least 8 characters long";
    } else if (new TextEncoder().encode(password).length > 72) {
      errors.password = "Password cannot exceed 72 bytes";
    }

    if (!confirmPassword) {
      errors.confirmPassword = "Confirm password is required";
    } else if (confirmPassword !== password) {
      errors.confirmPassword = "Passwords do not match";
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return; // Prevent duplicate submissions

    setError(null);
    if (!validateForm()) {
      return;
    }

    const submittedUsername = username.trim();
    const submittedPassword = password;
    setPassword("");
    setConfirmPassword("");
    setLoading(true);

    try {
      // Backend registration accepts only username and password, strictly provisioning the 'buyer' role
      await authService.register(submittedUsername, submittedPassword);
      setSuccess(true);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 400 && err.message?.toLowerCase().includes("already registered")) {
          setError("This username is already taken. Please choose another username.");
        } else if (err.status === 422) {
          setError(err.message || "Invalid registration data. Please verify password requirements.");
        } else {
          setError(err.message || "Registration failed. Please try again.");
        }
      } else {
        setError("An unexpected error occurred during registration. Please verify your connection.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground antialiased selection:bg-primary/15 selection:text-primary">
      {/* Top Application Bar */}
      <header className="w-full border-b border-border/80 bg-background/95 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link
            href="/"
            className="flex items-center gap-2 font-semibold text-foreground transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-md"
          >
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-2xs">
              <ShieldCheck className="size-4" aria-hidden="true" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold tracking-tight">ZK-SBOM Verify</span>
            </div>
          </Link>

          <div className="flex items-center gap-3">
            <ThemeToggle />
            <Link
              href="/"
              className={buttonVariants({ variant: "ghost", size: "sm", className: "gap-1.5 text-xs text-muted-foreground hover:text-foreground" })}
            >
              <ArrowLeft className="size-3.5" aria-hidden="true" />
              <span>Back to Home</span>
            </Link>
          </div>
        </div>
      </header>

      {/* Main Registration Card */}
      <main className="flex flex-1 items-center justify-center p-4 sm:p-6 lg:p-8 bg-muted/20">
        <Card className="w-full max-w-md shadow-xs border-border/80 bg-card">
          <CardHeader className="space-y-2 text-center pb-5">
            <div className="mx-auto flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary mb-1">
              <UserPlus className="size-5" aria-hidden="true" />
            </div>
            <CardTitle className="text-2xl font-bold tracking-tight">Request Platform Access</CardTitle>
            <CardDescription className="text-sm text-muted-foreground">
              Create a Buyer account to verify supply chain proofs and certificates
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {success ? (
              <div className="space-y-4 py-2">
                <Alert className="bg-success/10 text-foreground border-success/30 py-4">
                  <CheckCircle2 className="size-5 !text-emerald-700 dark:!text-emerald-300" aria-hidden="true" />
                  <AlertTitle className="text-sm font-semibold text-emerald-800 dark:text-emerald-300">
                    Registration Successful
                  </AlertTitle>
                  <AlertDescription className="text-xs text-muted-foreground mt-1 space-y-2">
                    <p>
                      Your account has been registered with standard <strong className="text-foreground">Buyer</strong> permissions. You can now sign in to inspect cryptographic verification certificates and SBOM compliance proofs.
                    </p>
                    <p className="text-[11px] text-muted-foreground font-mono">
                      Redirecting to sign-in in a few seconds...
                    </p>
                  </AlertDescription>
                </Alert>

                <Link
                  href="/login"
                  className={buttonVariants({ className: "w-full justify-center shadow-xs gap-2 font-semibold" })}
                >
                  <span>Proceed to Sign In</span>
                  <ArrowRight className="size-4" aria-hidden="true" />
                </Link>
              </div>
            ) : (
              <>
                {/* Role Transparency Callout */}
                <div className="rounded-lg border border-border/70 bg-muted/30 p-3 text-xs text-muted-foreground space-y-1">
                  <div className="font-semibold text-foreground flex items-center gap-1.5">
                    <Shield className="size-3.5 text-primary" aria-hidden="true" />
                    <span>Role: Standard Buyer (Self-Service)</span>
                  </div>
                  <p className="leading-relaxed text-[11px]">
                    Self-registration provisions a Buyer role for independent proof inspection, certificate validation, and threat catalog access. Vendor and Administrator privileges require administrative role assignments.
                  </p>
                </div>

                {error && (
                  <Alert variant="destructive" role="alert" className="py-3">
                    <AlertCircle className="size-4" aria-hidden="true" />
                    <AlertTitle className="text-xs font-semibold">Registration Failed</AlertTitle>
                    <AlertDescription className="text-xs mt-0.5">{error}</AlertDescription>
                  </Alert>
                )}

                <form onSubmit={handleRegister} className="space-y-4" noValidate>
                  {/* Username Field */}
                  <div className="space-y-1.5">
                    <Label htmlFor="register-username" className="text-xs font-medium text-foreground">
                      Username
                    </Label>
                    <Input
                      id="register-username"
                      name="username"
                      type="text"
                      placeholder="Choose a buyer username"
                      autoComplete="username"
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        if (validationErrors.username) {
                          setValidationErrors((prev) => ({ ...prev, username: undefined }));
                        }
                      }}
                      disabled={loading}
                      required
                      aria-invalid={!!validationErrors.username}
                      aria-describedby={validationErrors.username ? "register-username-error" : undefined}
                    />
                    {validationErrors.username && (
                      <p id="register-username-error" className="text-xs text-destructive font-medium">
                        {validationErrors.username}
                      </p>
                    )}
                  </div>

                  {/* Password Field with Show/Hide Toggle */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="register-password" className="text-xs font-medium text-foreground">
                        Password
                      </Label>
                      <span className="text-[10px] text-muted-foreground">Min. 8 characters</span>
                    </div>
                    <PasswordInput
                      id="register-password"
                      name="password"
                      placeholder="••••••••"
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        if (validationErrors.password) {
                          setValidationErrors((prev) => ({ ...prev, password: undefined }));
                        }
                      }}
                      disabled={loading}
                      required
                      aria-invalid={!!validationErrors.password}
                      aria-describedby={validationErrors.password ? "register-password-error" : undefined}
                    />
                    {validationErrors.password && (
                      <p id="register-password-error" className="text-xs text-destructive font-medium">
                        {validationErrors.password}
                      </p>
                    )}
                  </div>

                  {/* Confirm Password Field with Show/Hide Toggle */}
                  <div className="space-y-1.5">
                    <Label htmlFor="register-confirm-password" className="text-xs font-medium text-foreground">
                      Confirm Password
                    </Label>
                    <PasswordInput
                      id="register-confirm-password"
                      name="confirmPassword"
                      placeholder="••••••••"
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(e) => {
                        setConfirmPassword(e.target.value);
                        if (validationErrors.confirmPassword) {
                          setValidationErrors((prev) => ({ ...prev, confirmPassword: undefined }));
                        }
                      }}
                      disabled={loading}
                      required
                      aria-invalid={!!validationErrors.confirmPassword}
                      aria-describedby={validationErrors.confirmPassword ? "register-confirm-password-error" : undefined}
                    />
                    {validationErrors.confirmPassword && (
                      <p id="register-confirm-password-error" className="text-xs text-destructive font-medium">
                        {validationErrors.confirmPassword}
                      </p>
                    )}
                  </div>

                  {/* Submit Action */}
                  <Button type="submit" className="w-full font-semibold shadow-xs" disabled={loading}>
                    {loading ? (
                      <>
                        <Loader2 className="mr-2 size-4 animate-spin" aria-hidden="true" />
                        <span>Creating Account...</span>
                      </>
                    ) : (
                      <span>Create Buyer Account</span>
                    )}
                  </Button>
                </form>
              </>
            )}
          </CardContent>

          <CardFooter className="flex flex-col items-center justify-center border-t border-border/70 p-4 bg-muted/10 gap-1 text-center">
            <div className="text-xs text-muted-foreground">
              Already have an account?{" "}
              <Link href="/login" className="text-primary hover:underline font-medium">
                Sign In
              </Link>
            </div>
          </CardFooter>
        </Card>
      </main>
    </div>
  );
}
