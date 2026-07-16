import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0f1216",
        surface: "#161b22",
        border: "#232a34",
        text: "#dde3ea",
        muted: "#8b97a6",
        accent: "#5fb3ac",
        danger: "#e06c75",
        warn: "#e5a04c",
      },
    },
  },
  plugins: [],
};
export default config;
