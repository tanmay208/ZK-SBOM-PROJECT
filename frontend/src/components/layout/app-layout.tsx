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
  const isPublicHomePage = pathname === "/";

  // Render minimal public shell for login/register, public certificates, and the public homepage
  if (isAuthPage || isPublicCertificatePage || isPublicHomePage) {
    return <main className="flex min-h-screen flex-col bg-background text-foreground">{children}</main>;
  }

  return (
    <div className="grid min-h-screen w-full md:grid-cols-[240px_1fr] lg:grid-cols-[260px_1fr]">
      <Sidebar />
      <div className="flex flex-col flex-1 max-w-full overflow-hidden">
        <Header />
        <main className="flex flex-1 flex-col p-4 sm:p-6 lg:p-8 bg-muted/20 overflow-auto">
          <AppBreadcrumbs />
          <div className="flex flex-col flex-1 max-w-7xl mx-auto w-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
