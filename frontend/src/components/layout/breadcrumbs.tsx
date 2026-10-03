"use client";

import { usePathname } from "next/navigation";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import React from "react";
import { NAVIGATION_CONFIG } from "@/config/navigation";

export function AppBreadcrumbs() {
  const pathname = usePathname();
  
  if (pathname === "/") return null; // Don't show breadcrumbs on dashboard

  const paths = pathname.split("/").filter(Boolean);
  
  return (
    <Breadcrumb className="hidden md:flex mb-4">
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink href="/">Dashboard</BreadcrumbLink>
        </BreadcrumbItem>
        {paths.map((path, index) => {
          const href = `/${paths.slice(0, index + 1).join("/")}`;
          const isLast = index === paths.length - 1;
          
          // Try to find a human readable label from config
          const configMatch = NAVIGATION_CONFIG.find(item => item.href === href);
          
          // Format raw path segments
          let label = configMatch?.name || path.charAt(0).toUpperCase() + path.slice(1).replace(/-/g, " ");

          // Special mappings for specific Stage 7 cases:
          if (path === "upload" && paths[0] === "sboms") label = "Upload";
          if (path === "generate" && paths[0] === "proofs") label = "Generate";
          
          return (
            <React.Fragment key={href}>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                {isLast ? (
                  <BreadcrumbPage>{label}</BreadcrumbPage>
                ) : (
                  <BreadcrumbLink href={href}>{label}</BreadcrumbLink>
                )}
              </BreadcrumbItem>
            </React.Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
