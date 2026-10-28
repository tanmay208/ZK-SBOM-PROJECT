import * as React from "react"
import { cn } from "cn"

export interface PageHeaderProps extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  title: React.ReactNode
  description?: React.ReactNode
  badge?: React.ReactNode
  actions?: React.ReactNode
  headingLevel?: "h1" | "h2"
}

export function PageHeader({
  title,
  description,
  badge,
  actions,
  headingLevel = "h1",
  className,
  ...props
}: PageHeaderProps) {
  const HeadingTag = headingLevel

  return (
    <header
      data-slot="page-header"
      className={cn(
        "flex flex-col gap-4 border-b border-border/70 pb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-6",
        className
      )}
      {...props}
    >
      <div className="space-y-1.5 min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <HeadingTag className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl truncate">
            {title}
          </HeadingTag>
          {badge && <div className="shrink-0">{badge}</div>}
        </div>
        {description && (
          <p className="text-sm text-muted-foreground leading-relaxed max-w-3xl">
            {description}
          </p>
        )}
      </div>
      {actions && (
        <div className="flex shrink-0 flex-wrap items-center gap-2.5 pt-1 sm:pt-0">
          {actions}
        </div>
      )}
    </header>
  )
}
