import React from "react";

interface LogoProps extends React.SVGProps<SVGSVGElement> {
  size?: number;
  strokeWidth?: number;
  color?: string;
}

export function Logo({ size = 32, strokeWidth = 2.75, color = "currentColor", style, ...props }: LogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      stroke={color}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={style}
      aria-hidden="true"
      {...props}
    >
      <path d="M7 5 L12 17 L12 27" />
      <path d="M25 5 L20 17 L20 27" />
    </svg>
  );
}
