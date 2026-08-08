/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: 'rgb(3, 7, 18)', // bg-slate-950
        border: 'rgb(30, 41, 59)', // border-slate-800
      }
    },
  },
  plugins: [],
}
