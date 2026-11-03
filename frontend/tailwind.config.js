/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        sev: {
          critical: "#7f1d1d",
          high: "#b91c1c",
          medium: "#c2410c",
          low: "#a16207",
          info: "#1d4ed8",
        },
      },
    },
  },
  plugins: [],
};
