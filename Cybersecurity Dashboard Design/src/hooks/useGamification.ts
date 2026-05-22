import { useEffect, useState } from "react";

import {
  GAMIFICATION_UPDATED_AT_KEY,
  GAMIFICATION_UPDATED_EVENT,
  type GamificationOverview,
  fetchGamificationOverview,
} from "../utils/gamification";

export function useGamification() {
  const [overview, setOverview] = useState<GamificationOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = async (showLoader = false) => {
    if (showLoader) {
      setLoading(true);
    }

    try {
      const next = await fetchGamificationOverview();
      setOverview(next);
      setError(null);
    } catch (loadError) {
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load security progress."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(true);
  }, []);

  useEffect(() => {
    const handleUpdated = () => {
      void refresh(false);
    };

    const handleStorage = (event: StorageEvent) => {
      if (event.key === GAMIFICATION_UPDATED_AT_KEY) {
        void refresh(false);
      }
    };

    window.addEventListener(GAMIFICATION_UPDATED_EVENT, handleUpdated);
    window.addEventListener("storage", handleStorage);

    return () => {
      window.removeEventListener(GAMIFICATION_UPDATED_EVENT, handleUpdated);
      window.removeEventListener("storage", handleStorage);
    };
  }, []);

  return {
    overview,
    loading,
    error,
    refresh,
  };
}
