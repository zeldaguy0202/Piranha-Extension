// Minimal ambient types for the subset of the chrome.* extension APIs used in this project.
declare namespace chrome {
  namespace storage {
    interface StorageChange {
      oldValue?: unknown;
      newValue?: unknown;
    }

    interface StorageArea {
      get(
        keys: string | string[] | null,
        callback: (items: Record<string, any>) => void
      ): void;
      set(items: Record<string, any>, callback?: () => void): void;
    }

    const sync: StorageArea;

    const onChanged: {
      addListener(
        callback: (
          changes: Record<string, StorageChange>,
          areaName: string
        ) => void
      ): void;
      removeListener(
        callback: (
          changes: Record<string, StorageChange>,
          areaName: string
        ) => void
      ): void;
    };
  }

  namespace tabs {
    interface Tab {
      url?: string;
    }

    function query(
      queryInfo: { active?: boolean; currentWindow?: boolean },
      callback: (tabs: Tab[]) => void
    ): void;
  }

  namespace alarms {
    interface Alarm {
      name: string;
    }

    function create(name: string, alarmInfo: { periodInMinutes?: number }): void;

    const onAlarm: {
      addListener(callback: (alarm: Alarm) => void): void;
    };
  }

  namespace runtime {
    const onInstalled: {
      addListener(callback: () => void): void;
    };

    const onStartup: {
      addListener(callback: () => void): void;
    };
  }
}
