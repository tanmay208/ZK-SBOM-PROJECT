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

  return (
    <div className="hidden h-full w-64 flex-col border-r bg-muted/40 md:flex">
      <div className="flex h-14 items-center border-b px-4 lg:h-[60px] lg:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span className="text-lg">ZK-SBOM Verify</span>
        </Link>
      </div>
      <div className="flex-1 overflow-auto py-2">
        <nav className="grid items-start px-2 text-sm font-medium lg:px-4">
          {filteredNavItems.map((item) => {
            const isActive = isRouteActive(pathname, item.href, item.exactMatch);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? "page" : undefined}
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
    </div>
  );
}
