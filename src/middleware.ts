import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { cookies } from "next/headers";
import * as jose from "jose";

const routeThatDidntRequireAuth = ["/login", "/register"];

export async function middleware(request: NextRequest) {
  const cookiesList = cookies();
  const cookie = cookiesList.get("authToken");

  // If there is no authToken in cookies
  if (!cookie) {
    console.log("No auth cookie found");
    if (routeThatDidntRequireAuth.includes(request.nextUrl.pathname)) {
      return NextResponse.next();
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }

  try {
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
    await jose.jwtVerify(cookie.value, secret);
  } catch (error) {
    // If there is an authToken but he's not valid
    console.log("Cookie not valid");
    if (routeThatDidntRequireAuth.includes(request.nextUrl.pathname)) {
      return NextResponse.next();
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // If there is an authToken and he's valid, then user can go wherever he wants, except auth routes
  if (routeThatDidntRequireAuth.includes(request.nextUrl.pathname)) {
    return NextResponse.redirect(new URL("/", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
