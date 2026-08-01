import { NextResponse } from "next/server";
export function middleware(req) {
  if (!req.cookies.get("session")) {
    return NextResponse.redirect(new URL("/login", req.url));
  }
}
