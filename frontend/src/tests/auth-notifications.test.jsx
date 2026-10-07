// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axios from 'axios';
import { AuthProvider, useAuth } from '../contexts/AuthContext';

vi.mock('axios', () => ({ default: { get: vi.fn(), post: vi.fn() } }));
afterEach(() => { cleanup(); localStorage.clear(); vi.clearAllMocks(); });

function Account() {
  const { user, login, loading } = useAuth();
  return <>
    <button disabled={loading} onClick={() => login('test-user', 'test-password')}>Sign in</button>
    <span>{user?.notify_email}</span>
    <span>{user?.smtp_config?.host}</span>
  </>;
}

it('loads saved notification settings immediately after signing in', async () => {
  localStorage.clear();
  axios.post.mockResolvedValue({ data: { token: 'dummy-token', user: { id: 'test-user' } } });
  axios.get.mockResolvedValue({ data: { user: {
    id: 'test-user', notify_email: 'recipient@example.com',
    smtp_config: { host: 'smtp.example.com', pass: '••••••••' },
  } } });
  render(<AuthProvider><Account /></AuthProvider>);
  await waitFor(() => expect(screen.getByRole('button').disabled).toBe(false));
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  expect(await screen.findByText('recipient@example.com')).toBeTruthy();
  expect(screen.getByText('smtp.example.com')).toBeTruthy();
  expect(axios.get).toHaveBeenCalledWith('/api/auth/me', {
    headers: { Authorization: 'Bearer dummy-token' },
  });
});
