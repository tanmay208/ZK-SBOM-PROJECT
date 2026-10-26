"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useAuth } from "@/auth/AuthProvider";
import { ShieldCheck } from "lucide-react";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();

  const filteredNavItems = NAVIGATION_CONFIG.filter(
    (item) => !user || item.allowedRoles.includes(user.role)
  );

  // Group items by section
  const sections = Array.from(
    new Set(filteredNavItems.map((item) => item.section || "Navigation"))
  );

  return (
    <aside 
      aria-label="Sidebar navigation"
      className="hidden h-screen w-full flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground md:flex sticky top-0"
    >
      {/* Brand Header */}
      <div className="flex h-14 items-center justify-between border-b border-sidebar-border px-4 lg:h-[60px] lg:px-6">
        <Link 
          href="/dashboard" 
          className="flex items-center gap-2.5 font-semibold text-foreground transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-md"
        >
          <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-2xs">
            <ShieldCheck className="size-5" aria-hidden="true" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight">ZK-SBOM Verify</span>
            <span className="text-[10px] text-muted-foreground font-normal tracking-wide uppercase">Supply Chain Security</span>
          </div>
        </Link>
      </div>

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
        {sections.map((sectionName) => {
          const sectionItems = filteredNavItems.filter(
            (item) => (item.section || "Navigation") === sectionName
          );

          if (sectionItems.length === 0) return null;

          return (
            <div key={sectionName} className="space-y-1">
              <div className="px-3 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
                {sectionName}
              </div>
              <nav className="grid gap-0.5 text-sm font-medium">
                {sectionItems.map((item) => {
                  const isActive = isRouteActive(pathname, item.href, item.exactMatch);
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={isActive ? "page" : undefined}
                      className={cn(
                        "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        isActive
                          ? "bg-sidebar-accent text-primary font-semibold border-l-2 border-primary shadow-2xs"
                          : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
                      )}
                    >
                      <item.icon 
                        className={cn(
                          "size-4 shrink-0 transition-colors",
                          isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                        )} 
                        aria-hidden="true" 
                      />
                      <span className="truncate">{item.name}</span>
                    </Link>
                  );
                })}
              </nav>
            </div>
          );
        })}
      </div>

      {/* Local Node Information Panel */}
      <div className="border-t border-sidebar-border p-3.5 mt-auto">
        <div className="rounded-lg border border-sidebar-border/70 bg-sidebar-accent/30 p-2.5 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5 font-medium text-foreground">
            <span className="size-2 rounded-full bg-success shrink-0" aria-hidden="true" />
            <span className="truncate">Local Verification Node</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>Operating Mode</span>
            <span className="font-mono text-[10px] uppercase font-semibold text-primary">LOCAL-ONLY</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
