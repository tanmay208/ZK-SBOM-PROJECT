"use client";

import { Badge } from "@/components/ui/badge";
import { LogOut, Menu, ShieldCheck, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/auth/AuthProvider";
import { Sheet, SheetContent, SheetTrigger, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { ThemeToggle } from "./ThemeToggle";

function getRoleBadgeVariant(role: string) {
  switch (role) {
    case "admin":
      return "default";
    case "vendor":
      return "info";
    case "buyer":
      return "info";
    default:
      return "secondary";
  }
}

export function Header() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const filteredNavItems = NAVIGATION_CONFIG.filter(
    (item) => !user || item.allowedRoles.includes(user.role)
  );

  const sections = Array.from(
    new Set(filteredNavItems.map((item) => item.section || "Navigation"))
  );

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border/80 bg-card/95 backdrop-blur-xs px-4 lg:h-[60px] lg:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile Navigation Drawer */}
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger 
            className="md:hidden shrink-0 inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring border border-input bg-background shadow-2xs hover:bg-muted hover:text-foreground size-9" 
            aria-label="Open navigation menu"
          >
            <Menu className="size-5" />
          </SheetTrigger>
          <SheetContent side="left" className="w-[280px] sm:w-[320px] p-0 flex flex-col bg-sidebar text-sidebar-foreground">
            <div className="sr-only">
              <SheetTitle>Navigation Menu</SheetTitle>
              <SheetDescription>Mobile navigation drawer for ZK-SBOM Verify platform</SheetDescription>
            </div>
            <div className="flex h-14 items-center border-b border-sidebar-border px-4 lg:h-[60px]">
              <Link href="/dashboard" className="flex items-center gap-2.5 font-semibold" onClick={() => setOpen(false)}>
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <ShieldCheck className="size-5" />
                </div>
                <div className="flex flex-col">
                  <span className="text-sm font-bold tracking-tight">ZK-SBOM Verify</span>
                  <span className="text-[10px] text-muted-foreground font-normal tracking-wide uppercase">Supply Chain Security</span>
                </div>
              </Link>
            </div>
            <div className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
              {sections.map((sectionName) => {
                const sectionItems = filteredNavItems.filter(
                  (item) => (item.section || "Navigation") === sectionName
                );
                if (sectionItems.length === 0) return null;

                return (
                  <div key={sectionName} className="space-y-1">
                    <div className="px-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
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
                            onClick={() => setOpen(false)}
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
                            <span>{item.name}</span>
                          </Link>
                        );
                      })}
                    </nav>
                  </div>
                );
              })}
            </div>
            <div className="border-t border-sidebar-border p-3.5 mt-auto">
              <div className="rounded-lg border border-sidebar-border/70 bg-sidebar-accent/30 p-2.5 text-xs text-muted-foreground">
                <div className="flex items-center gap-1.5 font-medium text-foreground">
                  <span className="size-2 rounded-full bg-success shrink-0" aria-hidden="true" />
                  <span>Local Verification Node</span>
                </div>
                <div className="mt-1 flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>Operating Mode</span>
                  <span className="font-mono text-[10px] uppercase font-semibold text-primary">LOCAL-ONLY</span>
                </div>
              </div>
            </div>
          </SheetContent>
        </Sheet>

        {/* Brand identity shown on mobile when sidebar is hidden */}
        <div className="flex items-center gap-2 md:hidden">
          <ShieldCheck className="size-5 text-primary" />
          <span className="text-sm font-bold tracking-tight">ZK-SBOM</span>
        </div>
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        {/* Theme Toggle accessible across all breakpoints */}
        <ThemeToggle />

        {user && (
          <div className="flex items-center gap-2.5 pl-2 border-l border-border/70">
            <Link
              href="/profile"
              className="flex items-center gap-2 rounded-lg py-1 px-1.5 -ml-1.5 hover:bg-muted/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              title="View profile and account settings"
            >
              <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary font-semibold text-xs uppercase" aria-hidden="true">
                {user.username ? user.username.charAt(0) : <User className="size-3.5" />}
              </div>
              <span className="text-sm font-medium text-foreground hidden sm:inline-block max-w-[120px] truncate">
                {user.username}
              </span>
            </Link>
            <Badge variant={getRoleBadgeVariant(user.role)} className="capitalize text-[11px] py-0">
              {user.role.replace(/_/g, " ")}
            </Badge>
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={logout} 
              title="Log out" 
              aria-label="Log out"
              className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 size-8 transition-colors"
            >
              <LogOut className="size-4" />
              <span className="sr-only">Log out</span>
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
