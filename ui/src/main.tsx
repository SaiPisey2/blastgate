import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { LazyMotion, MotionConfig, domAnimation } from './motion';
// The new console layer loads first and the old stylesheet last, so while
// the old views are still wired their own rules win wherever the two
// define the same custom property at the same specificity.
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';
import './styles.css';

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
