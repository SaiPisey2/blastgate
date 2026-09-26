import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { LazyMotion, MotionConfig, domAnimation } from './motion';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';

function start() {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      {/* reducedMotion="user": people who ask the OS for less motion get no
          transform or layout animation. strict: a stray full `motion.div`
          would pull in every feature bundle and throw here, not ship. */}
      <MotionConfig reducedMotion="user">
        <LazyMotion features={domAnimation} strict>
          <App />
        </LazyMotion>
      </MotionConfig>
    </StrictMode>,
  );
}

// Demo fixtures, for looking at the console on the dev server with no
// cluster behind it (?demo). import.meta.env.DEV is false in a build, so
// this branch and the module it imports are dropped from dist/; the Go
// embed guard fails if the fixtures' marker ever ships.
const demo = new URLSearchParams(window.location.search).get('demo');
if (import.meta.env.DEV && demo !== null) {
  void import('./demo/fixtures').then((m) => {
    m.install(demo);
    start();
  });
} else {
  start();
}
