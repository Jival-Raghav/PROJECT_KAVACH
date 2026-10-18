/** @type {import('tailwindcss').Config} */
// Palette classes (slate, cyan, red, ...) resolve to theme variables in styles.css,
// so legacy utility classes follow the light/dark Mitigata themes automatically.
const v = name => `rgb(var(--tw-${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        white: v('ink'),
        onaccent: '#0A0A0A',
        slate: { 200: v('s200'), 300: v('s300'), 400: v('s400'), 500: v('s500'), 600: v('s600'), 700: v('s700'), 800: v('s800'), 900: v('s900'), 950: v('s950') },
        cyan:    { 300: v('g300'), 400: v('g400'), 500: v('g500'), 600: v('g600'), 800: v('g800'), 900: v('g900'), 950: v('g950') },
        emerald: { 300: v('g300'), 400: v('g400'), 500: v('g500'), 800: v('g800'), 950: v('g950') },
        red:     { 300: v('r300'), 400: v('r400'), 800: v('r800'), 950: v('r950') },
        rose:    { 400: v('r400'), 500: v('r500'), 800: v('r800'), 950: v('r950') },
        amber:   { 300: v('a300'), 400: v('a400'), 800: v('a800'), 950: v('a950') },
        indigo:  { 500: v('b500') },
        blue:    { 400: v('b400'), 800: v('b800'), 950: v('b950') },
      }
    }
  },
  plugins: []
}
