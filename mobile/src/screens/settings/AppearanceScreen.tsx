import { useAppearance } from '@/contexts/AppearanceContext'
import { Icon, I, Screen } from '@/components/ui/ds'
import { useHaptics } from '@/hooks/useHaptics'
import {
  APPEARANCE_DESCRIPTIONS,
  APPEARANCE_IDS,
  APPEARANCE_LABELS,
  type AppearanceId,
  type AppearancePreference,
  tokensFor,
} from '@/theme/appearance'

/**
 * Appearance — the same 9 looks + Auto as the web (Settings → Profile →
 * Appearance). Saved to the account, so web and app match.
 */
export default function AppearanceScreen() {
  const { preference, setPreference, saveError } = useAppearance()
  const haptics = useHaptics()
  const options: AppearancePreference[] = ['auto', ...APPEARANCE_IDS]

  const choose = (pref: AppearancePreference) => {
    void haptics.selection()
    void setPreference(pref)
  }

  return (
    <Screen title="Appearance" back="/more">
      <p className="text-sm text-[var(--muted)]">
        Choose how OraSec looks on this phone.
      </p>
      <div className="appearance-grid" role="radiogroup" aria-label="Appearance" data-testid="appearance-grid">
        {options.map((pref) => (
          <button
            key={pref}
            type="button"
            role="radio"
            aria-checked={preference === pref}
            className={`appearance-card${preference === pref ? ' on' : ''}`}
            onClick={() => choose(pref)}
            data-testid={`appearance-${pref}`}
          >
            {pref === 'auto' ? (
              <span className="appearance-preview split" aria-hidden="true">
                <Preview id="oraflows" />
                <Preview id="dark" />
              </span>
            ) : (
              <span className="appearance-preview" aria-hidden="true">
                <Preview id={pref} />
              </span>
            )}
            <span className="appearance-meta">
              <span className="appearance-name">
                {APPEARANCE_LABELS[pref]}
                {preference === pref && (
                  <span className="appearance-check">
                    <Icon d={I.check} size={14} stroke={2.4} />
                  </span>
                )}
              </span>
              <span className="appearance-desc">{APPEARANCE_DESCRIPTIONS[pref]}</span>
            </span>
          </button>
        ))}
      </div>
      {saveError && (
        <p className="text-sm text-[var(--warn)]" role="status">
          {saveError}
        </p>
      )}
    </Screen>
  )
}

/** A tiny screen drawn with the appearance's own tokens. */
function Preview({ id }: { id: AppearanceId }) {
  const t = tokensFor(id)
  const s = t.style
  return (
    <span className="ap-frame" style={{ background: s.pageBg, color: t.foreground, fontFamily: s.fontSans }}>
      <span className="ap-bar" style={{ background: s.topbarBg, borderBottom: `1px solid ${s.topbarBorder}` }}>
        <span className="ap-logo" style={{ background: s.logoBg }} />
        <span className="ap-line" style={{ background: t.foreground, width: '42%' }} />
      </span>
      <span
        className="ap-card"
        style={{ background: s.surface, boxShadow: s.raised, border: `${s.panelBorderWidth} solid ${s.panelBorder}`, borderRadius: 8 }}
      >
        <span className="ap-line" style={{ background: t.foreground, width: '70%' }} />
        <span className="ap-line sm" style={{ background: t.mutedForeground, width: '50%' }} />
        <span className="ap-row">
          <span className="ap-btn" style={{ background: t.primary }} />
          <span className="ap-btn" style={{ background: t.brand }} />
        </span>
      </span>
      <span className="ap-nav" style={{ background: s.sidebarBg, boxShadow: s.sidebarShadow }}>
        <span className="ap-dot" style={{ background: t.sidebar.activeText }} />
        <span className="ap-dot" style={{ background: t.sidebar.text, opacity: 0.6 }} />
        <span className="ap-dot" style={{ background: t.sidebar.text, opacity: 0.6 }} />
      </span>
    </span>
  )
}

