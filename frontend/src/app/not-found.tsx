import Link from "next/link";
import { buttonVariants } from "@/components/ui/button";
import { SearchX } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex h-screen w-full flex-col items-center justify-center space-y-6">
      <div className="flex flex-col items-center text-center space-y-4">
        <SearchX className="h-16 w-16 text-muted-foreground opacity-50" />
        <h1 className="text-4xl font-bold tracking-tight">404 - Not Found</h1>
        <p className="text-muted-foreground max-w-md">
          The requested resource, route, or identifier could not be found on the server.
          It may have been removed, or the ID may be invalid.
        </p>
      </div>
      <Link href="/" className={buttonVariants({ variant: "default" })}>
        Return to Safety
      </Link>
    </div>
  );
}
