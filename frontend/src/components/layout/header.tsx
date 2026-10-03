"use client";

import { Badge } from "@/components/ui/badge";
import { LogOut, Menu, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/auth/AuthProvider";
import { Sheet, SheetContent, SheetTrigger, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { ThemeToggle } from "./ThemeToggle";

export function Header() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const filteredNavItems = NAVIGATION_CONFIG.filter(
    (item) => !user || item.allowedRoles.includes(user.role)
  );

  return (
    <header className="flex h-14 items-center justify-between border-b bg-muted/40 px-4 lg:h-[60px] lg:px-6">
      <div className="flex items-center gap-4">
        {/* Mobile Navigation */}
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger 
            className="md:hidden shrink-0 inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground h-9 w-9" 
            aria-label="Open navigation menu"
          >
            <Menu className="h-5 w-5" />
          </SheetTrigger>
          <SheetContent side="left" className="w-[280px] sm:w-[320px] p-0 flex flex-col">
            <div className="sr-only">
              <SheetTitle>Navigation Menu</SheetTitle>
              <SheetDescription>Mobile navigation drawer for ZK-SBOM Verify platform</SheetDescription>
            </div>
            <div className="flex h-14 items-center border-b px-4 lg:h-[60px]">
              <Link href="/" className="flex items-center gap-2 font-semibold" onClick={() => setOpen(false)}>
                <ShieldCheck className="h-6 w-6 text-primary" />
                <span className="text-lg">ZK-SBOM Verify</span>
              </Link>
            </div>
            <div className="flex-1 overflow-auto py-2">
              <nav className="grid gap-1 px-2 text-sm font-medium">
                {filteredNavItems.map((item) => {
                  const isActive = isRouteActive(pathname, item.href, item.exactMatch);
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={isActive ? "page" : undefined}
                      onClick={() => setOpen(false)}
                      className={cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary focus:outline-none focus:ring-2 focus:ring-primary",
                        isActive
                          ? "bg-muted text-primary font-medium"
                          : "hover:bg-muted"
                      )}
                    >
                      <item.icon className="h-4 w-4" aria-hidden="true" />
                      {item.name}
                    </Link>
                  );
                })}
              </nav>
            </div>
          </SheetContent>
        </Sheet>
        
        {/* Theme Toggle */}
        <div className="hidden md:flex">
          <ThemeToggle />
        </div>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium hidden sm:inline-block">{user.username}</span>
            <Badge variant="secondary" className="capitalize">
              {user.role}
            </Badge>
            <Button variant="ghost" size="icon" onClick={logout} title="Log out" className="text-muted-foreground hover:text-foreground">
              <LogOut className="h-4 w-4" />
              <span className="sr-only">Log out</span>
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
