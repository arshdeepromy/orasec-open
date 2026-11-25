import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const env = vi.hoisted(() => ({ native: true, demo: false, optedIn: false }))
const api = vi.hoisted(() => ({ pushState: vi.fn(), pushSaveSettings: vi.fn(), pushTest: vi.fn() }))
const controller = vi.hoisted(() => ({ turnOnPush: vi.fn(), turnOffPush: vi.fn() }))

vi.mock('@/native/push', () => ({ pushSupported: () => env.native }))
vi.mock('@/demo/session', () => ({ isDemoSession: () => env.demo }))
vi.mock('@/hooks/useHaptics', () => ({ useHaptics: () => ({ medium: async () => {}, selection: async () => {} }) }))
vi.mock('@/api/orasec', () => ({ orasec: api, PUSH_KINDS: ['critical', 'approvals', 'alerts', 'overdue'] }))
vi.mock('@/notifications/pushController', () => ({ isPushOptedIn: () => env.optedIn, ...controller }))

import NotificationsScreen from '@/screens/settings/NotificationsScreen'

const SETTINGS = { critical: true, approvals: true, alerts: true, overdue: true }
const show = () => render(<MemoryRouter><NotificationsScreen /></MemoryRouter>)
const isOn = (id: string) => screen.getByTestId(id).getAttribute('aria-checked') === 'true'

describe('Notifications screen', () => {
  beforeEach(() => {
    Object.assign(env, { native: true, demo: false, optedIn: false })
    api.pushState.mockReset().mockResolvedValue({ available: true, registered: false, settings: SETTINGS })
    api.pushSaveSettings.mockReset()
    api.pushTest.mockReset()
    controller.turnOnPush.mockReset()
    controller.turnOffPush.mockReset()
  })

  it('is off until the person switches it on, and the kinds cannot be changed while it is off', async () => {
    show()
    await waitFor(() => expect(screen.getByTestId('push-toggle')).not.toBeDisabled())
    expect(isOn('push-toggle')).toBe(false)
    expect(screen.getByTestId('push-kind-critical')).toBeDisabled()
    expect(screen.queryByTestId('push-test')).toBeNull()
  })

  it('switching on shows the four kinds and the test button', async () => {
    controller.turnOnPush.mockResolvedValue({ ok: true, state: { available: true, registered: true, settings: SETTINGS } })
    show()
    await waitFor(() => expect(screen.getByTestId('push-toggle')).not.toBeDisabled())
    fireEvent.click(screen.getByTestId('push-toggle'))
    await waitFor(() => expect(isOn('push-toggle')).toBe(true))
    for (const kind of ['critical', 'alerts', 'approvals', 'overdue']) expect(isOn(`push-kind-${kind}`)).toBe(true)
    expect(screen.getByTestId('push-test')).toBeInTheDocument()
  })

  it('shows why when the phone refuses', async () => {
    controller.turnOnPush.mockResolvedValue({ ok: false, reason: 'denied', message: 'Notifications are switched off for OraSec in this phone’s settings.' })
    show()
    await waitFor(() => expect(screen.getByTestId('push-toggle')).not.toBeDisabled())
    fireEvent.click(screen.getByTestId('push-toggle'))
    await waitFor(() => expect(screen.getByTestId('push-notice')).toHaveTextContent('switched off for OraSec'))
    expect(isOn('push-toggle')).toBe(false)
  })

  it('saves one kind at a time and puts it back when saving fails', async () => {
    env.optedIn = true
    api.pushState.mockResolvedValue({ available: true, registered: true, settings: SETTINGS })
    api.pushSaveSettings.mockResolvedValueOnce({ available: true, registered: true, settings: { ...SETTINGS, overdue: false } })
    show()
    await waitFor(() => expect(screen.getByTestId('push-kind-overdue')).not.toBeDisabled())
    fireEvent.click(screen.getByTestId('push-kind-overdue'))
    await waitFor(() => expect(isOn('push-kind-overdue')).toBe(false))
    expect(api.pushSaveSettings).toHaveBeenCalledWith({ overdue: false })
    api.pushSaveSettings.mockRejectedValueOnce(new Error('offline'))
    fireEvent.click(screen.getByTestId('push-kind-critical'))
    await waitFor(() => expect(screen.getByTestId('push-notice')).toHaveTextContent('Could not save'))
    expect(isOn('push-kind-critical')).toBe(true)
  })

  it('sends a test and says what happened', async () => {
    env.optedIn = true
    api.pushState.mockResolvedValue({ available: true, registered: true, settings: SETTINGS })
    api.pushTest.mockResolvedValue({ ok: true, detail: '' })
    show()
    await waitFor(() => expect(screen.getByTestId('push-test')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('push-test'))
    await waitFor(() => expect(screen.getByTestId('push-notice')).toHaveTextContent('Test sent'))
  })

  it('explains itself in the demo, in the browser preview and when the server has no notifications', async () => {
    env.demo = true
    const first = show()
    await waitFor(() => expect(screen.getByTestId('push-blocked')).toHaveTextContent('demo'))
    expect(screen.getByTestId('push-toggle')).toBeDisabled()
    first.unmount()
    Object.assign(env, { demo: false, native: false })
    const second = show()
    await waitFor(() => expect(screen.getByTestId('push-blocked')).toHaveTextContent('installed OraSec app'))
    second.unmount()
    env.native = true
    api.pushState.mockResolvedValue({ available: false, registered: false, settings: SETTINGS })
    show()
    await waitFor(() => expect(screen.getByTestId('push-blocked')).toHaveTextContent('does not send notifications yet'))
    expect(screen.getByTestId('push-toggle')).toBeDisabled()
  })
})
