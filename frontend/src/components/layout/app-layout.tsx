"use client";

import { Sidebar } from "./sidebar";
import { Header } from "./header";
import { usePathname } from "next/navigation";
import { AppBreadcrumbs } from "./breadcrumbs";

export function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  
  // Public pages that do not get the authenticated shell (Sidebar/Header with user controls)
  const isAuthPage = pathname === "/login" || pathname === "/register";
  const isPublicCertificatePage = pathname.startsWith("/certificates/") && pathname.length > "/certificates/".length;

  // Render minimal public shell for login/register and unauthenticated public views
  // NOTE: If an authenticated user views the public certificate page, 
  // we could theoretically render the full shell, but the prompt says 
  // "Public users receive a minimal public shell". We'll respect the route-level
  // public distinction and give it the minimal shell to prevent confusion.
  if (isAuthPage || isPublicCertificatePage) {
    return <main className="flex min-h-screen flex-col">{children}</main>;
  }

  return (
    <div className="grid min-h-screen w-full md:grid-cols-[220px_1fr] lg:grid-cols-[280px_1fr]">
      <Sidebar />
      <div className="flex flex-col flex-1 max-w-full overflow-hidden">
        <Header />
        <main className="flex flex-1 flex-col gap-4 p-4 lg:gap-6 lg:p-6 bg-muted/20 overflow-auto">
          <AppBreadcrumbs />
          <div className="flex flex-col flex-1 max-w-7xl mx-auto w-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
