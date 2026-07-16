import NextAuth from "next-auth";
import Google from "next-auth/providers/google";

// Google ID tokens expire after ~1 hour. We request offline access so we get a
// refresh token, and refresh the ID token in the jwt callback when it expires,
// so the token forwarded to the backend stays valid across a long session.
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    Google({
      authorization: {
        params: { access_type: "offline", prompt: "consent", scope: "openid email profile" },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // First sign-in: persist the provider tokens.
      if (account) {
        token.id_token = account.id_token as string | undefined;
        token.access_token = account.access_token as string | undefined;
        token.refresh_token = account.refresh_token as string | undefined;
        token.expires_at = account.expires_at as number | undefined;
        token.error = undefined;
        return token;
      }
      // Still valid.
      if (token.expires_at && Date.now() < token.expires_at * 1000) {
        return token;
      }
      // Expired: refresh via Google's token endpoint.
      if (!token.refresh_token) return { ...token, error: "NoRefreshToken" };
      try {
        const res = await fetch("https://oauth2.googleapis.com/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: process.env.AUTH_GOOGLE_ID!,
            client_secret: process.env.AUTH_GOOGLE_SECRET!,
            grant_type: "refresh_token",
            refresh_token: token.refresh_token,
          }),
        });
        const refreshed = await res.json();
        if (!res.ok) throw refreshed;
        token.id_token = refreshed.id_token ?? token.id_token;
        token.access_token = refreshed.access_token;
        token.expires_at = Math.floor(Date.now() / 1000 + (refreshed.expires_in ?? 3600));
        if (refreshed.refresh_token) token.refresh_token = refreshed.refresh_token;
        token.error = undefined;
        return token;
      } catch {
        return { ...token, error: "RefreshFailed" };
      }
    },
    async session({ session, token }) {
      session.id_token = token.id_token;
      session.error = token.error;
      return session;
    },
  },
});
