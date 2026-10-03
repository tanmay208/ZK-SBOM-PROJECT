import {
  LayoutDashboard,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Award,
} from "lucide-react";

export type Role = "vendor" | "admin" | "auditor";

export interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  allowedRoles: Role[];
  exactMatch?: boolean;
}

export const NAVIGATION_CONFIG: NavItem[] = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard, allowedRoles: ["vendor", "admin", "auditor"], exactMatch: true },
  { name: "SBOM Management", href: "/sboms", icon: FileText, allowedRoles: ["vendor", "admin"] },
  { name: "Vulnerability Intel", href: "/admin/vulnerabilities", icon: ShieldAlert, allowedRoles: ["vendor", "admin", "auditor"] },
  { name: "Security Policies", href: "/admin/policies", icon: ShieldCheck, allowedRoles: ["vendor", "admin", "auditor"] },
  { name: "ZKP Workspace", href: "/proofs", icon: Zap, allowedRoles: ["vendor", "admin"] },
  { name: "Certificates", href: "/certificates", icon: Award, allowedRoles: ["vendor", "admin", "auditor"] },
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
