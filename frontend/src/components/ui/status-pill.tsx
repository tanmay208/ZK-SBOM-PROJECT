import * as React from "react"
import { Badge, type badgeVariants } from "@/components/ui/badge"
import type { VariantProps } from "class-variance-authority"
import { cn } from "cn"
import { 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  XCircle, 
  Lock, 
  ShieldCheck, 
  RotateCw 
} from "lucide-react"

export type SecurityStatus =
  | "verified"
  | "valid"
  | "active"
  | "completed"
  | "approved"
  | "committed"
  | "compliant"
  | "pending"
  | "queued"
  | "generating"
  | "in_progress"
  | "assembling_witness"
  | "running"
  | "frozen"
  | "revoked"
  | "failed"
  | "invalid"
  | "non_compliant"
  | "expired"
  | "execution_blocked"
  | string

export interface StatusPillProps extends React.HTMLAttributes<HTMLSpanElement> {
  status: SecurityStatus
  label?: string
  showIcon?: boolean
}

type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>["variant"]>

export function getStatusConfig(status: string): {
  variant: BadgeVariant
  icon: React.ComponentType<{ className?: string }> | null
  defaultLabel: string
} {
  const normalized = status.toLowerCase().replace(/[\s-]/g, "_")

  switch (normalized) {
    case "verified":
    case "valid":
    case "compliant":
      return { variant: "success", icon: ShieldCheck, defaultLabel: "Verified" }
    case "completed":
      return { variant: "success", icon: ShieldCheck, defaultLabel: "Completed" }
    case "active":
    case "approved":
      return { variant: "success", icon: CheckCircle2, defaultLabel: "Active" }
    case "committed":
      return { variant: "success", icon: CheckCircle2, defaultLabel: "Committed" }
    case "generating":
    case "in_progress":
      return { variant: "info", icon: RotateCw, defaultLabel: "In Progress" }
    case "assembling_witness":
      return { variant: "info", icon: RotateCw, defaultLabel: "Assembling Witness" }
    case "running":
      return { variant: "info", icon: RotateCw, defaultLabel: "Running" }
    case "pending":
    case "queued":
      return { variant: "warning", icon: Clock, defaultLabel: "Pending" }
    case "frozen":
      return { variant: "secondary", icon: Lock, defaultLabel: "Frozen" }
    case "warning":
    case "non_compliant":
      return { variant: "warning", icon: AlertTriangle, defaultLabel: "Warning" }
    case "revoked":
    case "invalid":
    case "failed":
    case "expired":
      return { variant: "destructive", icon: XCircle, defaultLabel: "Revoked" }
    case "execution_blocked":
      return { variant: "destructive", icon: XCircle, defaultLabel: "Execution Blocked" }
    default:
      return { variant: "secondary", icon: null, defaultLabel: status }
  }
}

export function StatusPill({
  status,
  label,
  showIcon = true,
  className,
  ...props
}: StatusPillProps) {
  const config = getStatusConfig(status)
  const Icon = config.icon
  const displayLabel = label ?? config.defaultLabel

  return (
    <Badge
      variant={config.variant}
      className={cn("gap-1.5 font-medium px-2 py-0.5", className)}
      {...props}
    >
      {showIcon && Icon && <Icon className="size-3.5 shrink-0" aria-hidden="true" />}
      <span className="capitalize">{displayLabel}</span>
    </Badge>
  )
}
