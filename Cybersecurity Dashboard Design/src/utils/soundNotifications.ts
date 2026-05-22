/**
 * Sound Notification System
 * Provides audio feedback for security alerts and analysis completion
 */

type SoundType = 'success' | 'error' | 'warning' | 'alert' | 'critical';

// Lazy-loaded audio context
let audioContextInstance: AudioContext | null = null;

/**
 * Get or create the audio context
 */
function getAudioContext(): AudioContext | null {
  if (typeof window === 'undefined') return null;
  
  try {
    if (!audioContextInstance) {
      const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
      audioContextInstance = new AudioContextClass();
    }
    
    // Resume context if suspended (required by browsers for autoplay policies)
    if (audioContextInstance.state === 'suspended') {
      audioContextInstance.resume().catch((err) => {
        console.warn('Could not resume audio context:', err);
      });
    }
    
    return audioContextInstance;
  } catch (err) {
    console.warn('Audio Context not available:', err);
    return null;
  }
}

/**
 * Generate a simple beep sound using Web Audio API
 * @param frequency - Frequency in Hz
 * @param duration - Duration in milliseconds
 * @param volume - Volume (0-1)
 */
function playBeep(
  frequency: number = 800,
  duration: number = 300,
  volume: number = 0.3
): void {
  try {
    const ctx = getAudioContext();
    if (!ctx) {
      console.warn('Audio context unavailable');
      return;
    }

    const now = ctx.currentTime;
    const durationInSeconds = duration / 1000;

    // Create oscillator
    const osc = ctx.createOscillator();
    osc.frequency.value = frequency;
    osc.type = 'sine';

    // Create gain node for volume and envelope
    const gainNode = ctx.createGain();
    gainNode.gain.setValueAtTime(volume, now);
    gainNode.gain.exponentialRampToValueAtTime(
      0.01,
      now + durationInSeconds
    );

    // Connect and start
    osc.connect(gainNode);
    gainNode.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + durationInSeconds);
  } catch (err) {
    console.warn('Audio playback failed:', err);
  }
}

/**
 * Play a success notification sound
 * Used for completed analysis, security checks, etc.
 */
export function playSuccessSound(): void {
  try {
    // Two ascending beeps for success
    playBeep(800, 200, 0.3);
    setTimeout(() => {
      playBeep(1000, 200, 0.3);
    }, 150);
  } catch (err) {
    console.warn('Could not play success sound:', err);
  }
}

/**
 * Play a warning notification sound
 * Used for suspicious findings or moderate alerts
 */
export function playWarningSound(): void {
  try {
    // Single mid-frequency beep
    playBeep(650, 400, 0.35);
  } catch (err) {
    console.warn('Could not play warning sound:', err);
  }
}

/**
 * Play a critical alert sound
 * Used for severe threats or failures
 */
export function playCriticalSound(): void {
  try {
    // Three rapid high-pitched beeps
    playBeep(1200, 150, 0.4);
    setTimeout(() => {
      playBeep(1200, 150, 0.4);
    }, 100);
    setTimeout(() => {
      playBeep(1200, 150, 0.4);
    }, 200);
  } catch (err) {
    console.warn('Could not play critical sound:', err);
  }
}

/**
 * Play an error notification sound
 * Used for failed operations or errors
 */
export function playErrorSound(): void {
  try {
    // Two descending beeps for error
    playBeep(800, 200, 0.3);
    setTimeout(() => {
      playBeep(600, 250, 0.3);
    }, 150);
  } catch (err) {
    console.warn('Could not play error sound:', err);
  }
}

/**
 * Play a generic alert sound
 */
export function playAlertSound(): void {
  try {
    playBeep(900, 300, 0.3);
  } catch (err) {
    console.warn('Could not play alert sound:', err);
  }
}

/**
 * Check if audio notifications are enabled (respects user preferences)
 */
export function areAudioNotificationsEnabled(): boolean {
  if (typeof window === 'undefined') return false;
  
  try {
    const stored = localStorage.getItem('sentinel_audio_notifications_enabled');
    // Default to true if not set
    return stored !== 'false';
  } catch {
    return true;
  }
}

/**
 * Toggle audio notifications
 */
export function toggleAudioNotifications(enabled: boolean): void {
  if (typeof window === 'undefined') return;
  
  try {
    localStorage.setItem(
      'sentinel_audio_notifications_enabled',
      String(enabled)
    );
  } catch (err) {
    console.warn('Could not save audio notification preference:', err);
  }
}

/**
 * Conditional play with user preference check
 */
export function playConditionalSound(type: SoundType): void {
  if (!areAudioNotificationsEnabled()) return;

  switch (type) {
    case 'success':
      playSuccessSound();
      break;
    case 'warning':
      playWarningSound();
      break;
    case 'critical':
      playCriticalSound();
      break;
    case 'error':
      playErrorSound();
      break;
    case 'alert':
      playAlertSound();
      break;
  }
}

/**
 * Initialize audio context on user interaction
 * Must be called in response to user gesture for autoplay to work
 */
export function initializeAudioContext(): void {
  try {
    const ctx = getAudioContext();
    if (ctx && ctx.state === 'suspended') {
      ctx.resume();
    }
  } catch (err) {
    console.warn('Could not initialize audio context:', err);
  }
}

