import {
  LayoutDashboard,
  FileText,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Award,
  CheckCircle2,
  User,
  Users,
  AppWindow,
} from "lucide-react";

export type Role = "vendor" | "admin" | "buyer";

export interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  allowedRoles: Role[];
  exactMatch?: boolean;
  section?: string;
}

export const NAVIGATION_CONFIG: NavItem[] = [
  // Core Workspace
  {
    name: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
    allowedRoles: ["vendor", "admin", "buyer"],
    exactMatch: true,
    section: "Workspace",
  },
  {
    name: "Applications",
    href: "/applications",
    icon: AppWindow,
    allowedRoles: ["vendor", "admin"],
    section: "Workspace",
  },
  {
    name: "SBOM Management",
    href: "/sboms",
    icon: FileText,
    allowedRoles: ["vendor", "admin"],
    section: "Workspace",
  },
  {
    name: "Profile & Settings",
    href: "/profile",
    icon: User,
    allowedRoles: ["vendor", "admin", "buyer"],
    exactMatch: true,
    section: "Workspace",
  },

  // Zero-Knowledge Evidence Pipeline
  {
    name: "ZKP Workspace",
    href: "/proofs",
    icon: Zap,
    allowedRoles: ["vendor", "admin"],
    section: "Zero-Knowledge",
  },
  {
    name: "Proof Verification",
    href: "/verify",
    icon: CheckCircle2,
    allowedRoles: ["vendor", "admin", "buyer"],
    section: "Zero-Knowledge",
  },
  {
    name: "Certificates",
    href: "/certificates",
    icon: Award,
    allowedRoles: ["vendor", "admin", "buyer"],
    section: "Zero-Knowledge",
  },

  // Security Governance & Intelligence
  {
    name: "Administration",
    href: "/admin",
    icon: Shield,
    allowedRoles: ["admin"],
    exactMatch: true,
    section: "Governance & Intel",
  },
  {
    name: "User Management",
    href: "/admin/users",
    icon: Users,
    allowedRoles: ["admin"],
    section: "Governance & Intel",
  },
  {
    name: "Security Policies",
    href: "/admin/policies",
    icon: ShieldCheck,
    allowedRoles: ["vendor", "admin", "buyer"],
    section: "Governance & Intel",
  },
  {
    name: "Vulnerability Intel",
    href: "/admin/vulnerabilities",
    icon: ShieldAlert,
    allowedRoles: ["vendor", "admin", "buyer"],
    section: "Governance & Intel",
  },
];

/**
 * Checks if a given path matches a navigation item.
 * Supports exact matching (for root '/') and prefix matching (for nested routes).
 */
export function isRouteActive(pathname: string, href: string, exactMatch = false): boolean {
  if (exactMatch) {
    return pathname === href;
  }
  return pathname.startsWith(href);
}
