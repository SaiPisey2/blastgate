import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Login from './Login';
import { mockFetch } from '../test/fetch';

afterEach(cleanup);

describe('Login', () => {
  it('login clears the field and never stores the token', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const calls = mockFetch({ 'POST /api/login': { body: { name: 'bob', csrf: 'c1' } } });
    const onSignedIn = vi.fn();
    render(<Login onSignedIn={onSignedIn} />);
    const field = screen.getByLabelText(/login token/i) as HTMLInputElement;
    await userEvent.type(field, 'bga_secret-token');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith({ name: 'bob', csrf: 'c1' }));
    expect(field.value).toBe('');
    expect(JSON.parse(calls[0].body!)).toEqual({ token: 'bga_secret-token' });
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).not.toContain('bga_');
  });

  it('says so when the token is refused, and still clears it', async () => {
    mockFetch({ 'POST /api/login': { status: 401, body: { error: 'unauthorized' } } });
    render(<Login onSignedIn={() => {}} />);
    const field = screen.getByLabelText(/login token/i) as HTMLInputElement;
    await userEvent.type(field, 'bga_wrong{Enter}');
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(field.value).toBe('');
  });
});
