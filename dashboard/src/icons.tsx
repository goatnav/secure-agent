import type { SVGProps } from "react";
type Props = SVGProps<SVGSVGElement> & { size?: number };
const icon =
  (paths: string[]) =>
  ({ size = 24, ...props }: Props) => (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {paths.map((d, i) => (
        <path d={d} key={i} />
      ))}
    </svg>
  );
export const ShieldCheck = icon([
  "M12 3 20 6v6c0 5-8 9-8 9S4 17 4 12V6Z",
  "m8 12 3 3 5-6",
]);
export const Activity = icon(["M3 12h4l3-8 4 16 3-8h4"]);
export const FileCheck2 = icon([
  "M14 3H5v18h14V8Z",
  "M14 3v5h5",
  "m8 14 2 2 5-5",
]);
export const ScrollText = icon([
  "M5 4h14v15H5Z",
  "M8 8h8M8 12h8M8 16h5",
  "M3 4v3M21 19v-3",
]);
export const ArrowUpRight = icon(["M6 18 18 6M6 6h12v12"]);
export const LockKeyhole = icon([
  "M6 10h12v11H6Z",
  "M8 10V7a4 4 0 0 1 8 0v3",
  "M12 14v3",
]);
export const LogOut = icon(["M10 4H4v16h6", "M9 12h12m-4-4 4 4-4 4"]);
export const Plus = icon(["M12 5v14M5 12h14"]);
export const Search = icon([
  "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14",
  "m15 15 6 6",
]);
export const Check = icon(["m5 12 4 4L19 6"]);
export const X = icon(["m6 6 12 12M18 6 6 18"]);
export const Circle = ({ size = 24, ...props }: Props) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    aria-hidden="true"
    {...props}
  >
    <circle cx="12" cy="12" r="9" />
  </svg>
);
export const Layers3 = icon([
  "m12 3 10 5-10 5L2 8Z",
  "m2 12 10 5 10-5",
  "m2 16 10 5 10-5",
]);
