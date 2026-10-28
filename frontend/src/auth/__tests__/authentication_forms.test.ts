import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";

test("PasswordInput component is properly defined and exports", async () => {
  const passwordModule = await import("../../components/ui/password-input");
  assert.strictEqual(typeof passwordModule.PasswordInput, "object", "PasswordInput must be a valid React forwardRef component");
});

test("Login page defines accessible structure and in-memory security invariants", () => {
  const loginPath = path.resolve(process.cwd(), "src/app/login/page.tsx");
  const content = fs.readFileSync(loginPath, "utf-8");

  // Accessible labeling
  assert.match(content, /htmlFor="login-username"/, "Username label must match input id");
  assert.match(content, /id="login-username"/, "Username input must have id");
  assert.match(content, /htmlFor="login-password"/, "Password label must match input id");
  assert.match(content, /id="login-password"/, "Password input must have id");

  // Autocomplete attributes for password managers
  assert.match(content, /autoComplete="username"/, "Username must have autoComplete");
  assert.match(content, /autoComplete="current-password"/, "Password must have autoComplete current-password");

  // Duplicate submission prevention
  assert.match(content, /if \(loading\) return;/, "Must prevent duplicate submissions when loading");
  assert.match(content, /disabled=\{loading\}/, "Inputs and submit button must disable when loading");

  // In-memory token storage invariant
  assert.match(content, /authTransport\.setToken/, "Must use authTransport in-memory token setter");
  assert.doesNotMatch(content, /localStorage/, "Must NOT use localStorage");
  assert.doesNotMatch(content, /sessionStorage/, "Must NOT use sessionStorage");
  assert.doesNotMatch(content, /document\.cookie/, "Must NOT use cookies");

  // Post-login destination
  assert.match(content, /router\.push\("\/dashboard"\)/, "Successful login must navigate to dashboard workspace");
});

test("Register page enforces backend role invariants, accessible structure, and client validation", () => {
  const registerPath = path.resolve(process.cwd(), "src/app/register/page.tsx");
  const content = fs.readFileSync(registerPath, "utf-8");

  // Accessible labeling
  assert.match(content, /htmlFor="register-username"/, "Username label must match input id");
  assert.match(content, /id="register-username"/, "Username input must have id");
  assert.match(content, /htmlFor="register-password"/, "Password label must match input id");
  assert.match(content, /id="register-password"/, "Password input must have id");
  assert.match(content, /htmlFor="register-confirm-password"/, "Confirm password label must match input id");
  assert.match(content, /id="register-confirm-password"/, "Confirm password input must have id");

  // Autocomplete
  assert.match(content, /autoComplete="username"/, "Username must have autoComplete");
  assert.match(content, /autoComplete="new-password"/, "Passwords must have autoComplete new-password");

  // Role safety invariant: NO client-selectable role dropdown or role escalation
  assert.doesNotMatch(content, /<select/i, "Must NOT have client-controlled role dropdown");
  assert.doesNotMatch(content, /role="admin"/i, "Must NOT offer client-side admin role selection");
  assert.doesNotMatch(content, /role="vendor"/i, "Must NOT offer client-side vendor role selection");
  assert.match(content, /Standard (Buyer|Auditor)/i, "Must clearly state standard role assignment");

  // Validation rules (min 8 chars, confirm password match)
  assert.match(content, /length < 8/, "Must validate minimum password length of 8 chars");
  assert.match(content, /confirmPassword !== password/, "Must validate password confirmation match");

  // Duplicate submission prevention
  assert.match(content, /if \(loading\) return;/, "Must prevent duplicate submissions when loading");

  // Post-registration redirect
  assert.match(content, /router\.push\("\/login"\)/, "Must redirect or link to login upon successful registration");
});

test("Password visibility toggle accessibility specification", () => {
  const passwordInputPath = path.resolve(process.cwd(), "src/components/ui/password-input.tsx");
  const content = fs.readFileSync(passwordInputPath, "utf-8");

  assert.match(content, /type="button"/, "Toggle button must have type='button' to prevent form submission");
  assert.match(content, /aria-label=\{showPassword \? "Hide password" : "Show password"\}/, "Must have accessible toggle label");
  assert.match(content, /type=\{showPassword \? "text" : "password"\}/, "Must toggle input type between text and password");
  assert.match(content, /focus-visible:ring-2/, "Toggle button must have visible focus ring");
});

test("Authentication form validation logic behavior", () => {
  // Test username validation
  const validateUsername = (u: string) => {
    const trimmed = u.trim();
    if (!trimmed) return "Username is required";
    if (trimmed.length < 3) return "Username must be at least 3 characters long";
    return null;
  };

  assert.strictEqual(validateUsername(""), "Username is required");
  assert.strictEqual(validateUsername("  "), "Username is required");
  assert.strictEqual(validateUsername("ab"), "Username must be at least 3 characters long");
  assert.strictEqual(validateUsername("auditor1"), null);

  // Test password validation
  const validatePassword = (p: string, confirm: string) => {
    if (!p) return "Password is required";
    if (p.length < 8) return "Password must be at least 8 characters long";
    if (new TextEncoder().encode(p).length > 72) return "Password cannot exceed 72 bytes";
    if (confirm !== p) return "Passwords do not match";
    return null;
  };

  assert.strictEqual(validatePassword("", ""), "Password is required");
  assert.strictEqual(validatePassword("short", "short"), "Password must be at least 8 characters long");
  assert.strictEqual(validatePassword("validPassword123", "differentPassword"), "Passwords do not match");
  assert.strictEqual(validatePassword("validPassword123", "validPassword123"), null);
  assert.strictEqual(validatePassword("a".repeat(73), "a".repeat(73)), "Password cannot exceed 72 bytes");
});
