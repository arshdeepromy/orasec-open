import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const server = vi.hoisted(() => ({ url: '', native: true, check: vi.fn(), presets: [] as Array<{ label: string; url: string }> }))
const auth = vi.hoisted(() => ({ link: vi.fn(), startDemo: vi.fn() }))
const browser = vi.hoisted(() => ({ openExternalUrl: vi.fn() }))
const brand = vi.hoisted(() => ({ SOURCE_URL: 'https://github.com/example/orasec', PRIVACY_POLICY_URL: 'https://example.com/privacy', PUBLISHER: 'Example Ltd' }))

vi.mock('@/config/serverConfig', () => ({
  get SERVER_PRESETS() {
    return server.presets
  },
  hasServer: () => !server.native || server.url !== '',
  getDisplayServerUrl: () => server.url.replace(/^https?:\/\//, ''),
  webAppUrl: (path = '') => `${server.url}${path}`,
  normalizeServerUrl: (input: string) => (/^https?:\/\//.test(input) || input.includes('.') ? `https://${input.replace(/^https?:\/\//, '')}` : null),
  addressProblem: () => 'Enter the address of your OraSec server, for example orasec.example.com',
  checkServer: server.check,
  setServerUrl: async (url: string) => {
    server.url = url
    return url
  },
}))
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ ...auth, signedOutReason: null }) }))
vi.mock('@/native/browser', () => browser)
vi.mock('@/config/brand', () => brand)
vi.mock('@/hooks/useLayout', () => ({ useLayout: () => ({ isTablet: false, size: 'phone' }) }))
vi.mock('@/security/appPin', () => ({ takeSignInNotice: () => null }))

import LinkScreen from '@/screens/LinkScreen'

const show = () => render(<MemoryRouter><LinkScreen /></MemoryRouter>)

describe('Link screen: the server address comes first', () => {
  beforeEach(() => {
    Object.assign(server, { url: '', native: true, presets: [] })
    brand.SOURCE_URL = 'https://github.com/example/orasec'
    server.check.mockReset()
    auth.link.mockReset()
    auth.startDemo.mockReset()
    browser.openExternalUrl.mockReset()
  })

  it('asks for the server when the app knows none, and still offers the demo', () => {
    show()
    expect(screen.getByTestId('server-step')).toBeInTheDocument()
    expect(screen.getByTestId('server-address')).toHaveValue('')
    expect(screen.getByTestId('server-submit')).toBeDisabled()
    expect(screen.queryByTestId('link-code')).toBeNull()
    expect(screen.getByTestId('try-demo')).toBeInTheDocument()
    expect(screen.queryByTestId('server-cancel')).toBeNull()
  })

  it('checks the address, then shows the link code step with the server name', async () => {
    server.check.mockResolvedValue({ ok: true, url: 'https://orasec.example.com' })
    show()
    fireEvent.change(screen.getByTestId('server-address'), { target: { value: 'orasec.example.com' } })
    fireEvent.click(screen.getByTestId('server-submit'))
    await waitFor(() => expect(screen.getByTestId('link-code')).toBeInTheDocument())
    expect(server.check).toHaveBeenCalledWith('orasec.example.com')
    expect(screen.getByTestId('server-name')).toHaveTextContent('orasec.example.com')
    expect(screen.queryByTestId('server-step')).toBeNull()
  })

  it('says why when the address is not an OraSec server, and stays on the step', async () => {
    server.check.mockResolvedValue({ ok: false, message: 'That address did not answer like an OraSec server. Check it with your administrator.' })
    show()
    fireEvent.change(screen.getByTestId('server-address'), { target: { value: 'example.com' } })
    fireEvent.click(screen.getByTestId('server-submit'))
    await waitFor(() => expect(screen.getByTestId('server-error')).toHaveTextContent('did not answer like an OraSec server'))
    expect(screen.queryByTestId('link-code')).toBeNull()
    expect(server.url).toBe('')
  })

  it('does not ask the network about something that is not an address', async () => {
    show()
    fireEvent.change(screen.getByTestId('server-address'), { target: { value: 'orasec' } })
    fireEvent.click(screen.getByTestId('server-submit'))
    await waitFor(() => expect(screen.getByTestId('server-error')).toBeInTheDocument())
    expect(server.check).not.toHaveBeenCalled()
  })

  it('goes straight to the link code when the server is known, and lets the person change it', async () => {
    server.url = 'https://orasec.example.com'
    server.check.mockResolvedValue({ ok: true, url: 'https://other.example.com' })
    show()
    expect(screen.getByTestId('link-code')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('server-change'))
    expect(screen.getByTestId('server-address')).toHaveValue('orasec.example.com')
    fireEvent.click(screen.getByTestId('server-cancel'))
    expect(screen.getByTestId('server-name')).toHaveTextContent('orasec.example.com')
    fireEvent.click(screen.getByTestId('server-change'))
    fireEvent.change(screen.getByTestId('server-address'), { target: { value: 'other.example.com' } })
    fireEvent.click(screen.getByTestId('server-submit'))
    await waitFor(() => expect(screen.getByTestId('server-name')).toHaveTextContent('other.example.com'))
  })

  it('points people without a server to the source code', () => {
    show()
    fireEvent.click(screen.getByTestId('host-your-own'))
    expect(browser.openExternalUrl).toHaveBeenCalledWith('https://github.com/example/orasec')
  })

  it('shows no source link until the publisher sets one', () => {
    brand.SOURCE_URL = ''
    show()
    expect(screen.queryByTestId('host-your-own')).toBeNull()
  })

  it('offers development presets only when the build has them', async () => {
    show()
    expect(screen.queryByTestId('server-presets')).toBeNull()
  })
})
