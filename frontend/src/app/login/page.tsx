"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { authService } from "@/api/services/authService";
import { authTransport } from "@/api/authTransport";
import { useAuth } from "@/auth/AuthProvider";
import { ApiError } from "@/api/errors";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordInput } from "@/components/ui/password-input";
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from "@/components/ui/card";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { ShieldCheck, AlertCircle, Loader2, ArrowLeft, KeyRound, Lock } from "lucide-react";
import Link from "next/link";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<{ username?: string; password?: string }>({});
  const router = useRouter();
  const { refetchUser, status } = useAuth();

  // If already authenticated, redirect to dashboard workspace
  useEffect(() => {
    if (status === "authenticated") {
      router.push("/dashboard");
    }
  }, [status, router]);

  const validateForm = (): boolean => {
    const errors: { username?: string; password?: string } = {};
    if (!username.trim()) {
      errors.username = "Username is required";
    }
    if (!password) {
      errors.password = "Password is required";
    }
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return; // Prevent duplicate submission

    setError(null);
    if (!validateForm()) {
      return;
    }

    const submittedUsername = username.trim();
    const submittedPassword = password;
    setPassword(""); // Clear sensitive password input
    setLoading(true);

    try {
      const response = await authService.login(submittedUsername, submittedPassword);
      // STRICT INVARIANT: Token stored ONLY in memory. Zero persistent browser storage.
      authTransport.setToken(response.access_token);
      
      // Bootstrap the active user session
      await authService.me();
      refetchUser();
      
      // Navigate to protected workspace
      router.push("/dashboard");
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError("Incorrect username or password. Please check your credentials and try again.");
        } else {
          setError(err.message || "Authentication failed. Please try again.");
        }
      } else {
        setError("An unexpected error occurred during sign-in. Please verify your connection.");
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

      {/* Main Authentication Card */}
      <main className="flex flex-1 items-center justify-center p-4 sm:p-6 lg:p-8 bg-muted/20">
        <Card className="w-full max-w-md shadow-xs border-border/80 bg-card">
          <CardHeader className="space-y-2 text-center pb-5">
            <div className="mx-auto flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary mb-1">
              <Lock className="size-5" aria-hidden="true" />
            </div>
            <CardTitle className="text-2xl font-bold tracking-tight">Sign In to Workspace</CardTitle>
            <CardDescription className="text-sm text-muted-foreground">
              Zero-Knowledge Software Supply Chain Verification
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {error && (
              <Alert variant="destructive" role="alert" className="py-3">
                <AlertCircle className="size-4" aria-hidden="true" />
                <AlertTitle className="text-xs font-semibold">Sign In Failed</AlertTitle>
                <AlertDescription className="text-xs mt-0.5">{error}</AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleLogin} className="space-y-4" noValidate>
              {/* Username Field */}
              <div className="space-y-1.5">
                <Label htmlFor="login-username" className="text-xs font-medium text-foreground">
                  Username
                </Label>
                <Input
                  id="login-username"
                  name="username"
                  type="text"
                  placeholder="Enter your username"
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
                  aria-describedby={validationErrors.username ? "login-username-error" : undefined}
                />
                {validationErrors.username && (
                  <p id="login-username-error" className="text-xs text-destructive font-medium">
                    {validationErrors.username}
                  </p>
                )}
              </div>

              {/* Password Field with Show/Hide Toggle */}
              <div className="space-y-1.5">
                <Label htmlFor="login-password" className="text-xs font-medium text-foreground">
                  Password
                </Label>
                <PasswordInput
                  id="login-password"
                  name="password"
                  placeholder="••••••••"
                  autoComplete="current-password"
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
                  aria-describedby={validationErrors.password ? "login-password-error" : undefined}
                />
                {validationErrors.password && (
                  <p id="login-password-error" className="text-xs text-destructive font-medium">
                    {validationErrors.password}
                  </p>
                )}
              </div>

              {/* Submit Action */}
              <Button type="submit" className="w-full font-semibold shadow-xs" disabled={loading}>
                {loading ? (
                  <>
                    <Loader2 className="mr-2 size-4 animate-spin" aria-hidden="true" />
                    <span>Signing In...</span>
                  </>
                ) : (
                  <span>Sign In</span>
                )}
              </Button>
            </form>

            {/* In-Memory Privacy Assurance Callout */}
            <div className="flex items-center justify-center gap-1.5 pt-2 text-[11px] text-muted-foreground font-mono">
              <KeyRound className="size-3 text-primary" aria-hidden="true" />
              <span>In-memory session token &bull; Zero persistent storage</span>
            </div>
          </CardContent>

          <CardFooter className="flex flex-col items-center justify-center border-t border-border/70 p-4 bg-muted/10 gap-1 text-center">
            <div className="text-xs text-muted-foreground">
              Don&apos;t have an account?{" "}
              <Link href="/register" className="text-primary hover:underline font-medium">
                Register as Buyer
              </Link>
            </div>
          </CardFooter>
        </Card>
      </main>
    </div>
  );
}
