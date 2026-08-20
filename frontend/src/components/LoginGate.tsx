/**
 * The sign-in gate: password + PIN, both required.
 *
 * Three things this deliberately does NOT do:
 *  - it does not hold the credentials in React state longer than the submit, and never in
 *    localStorage: the session is an HttpOnly cookie the page cannot read, which is the point;
 *  - it does not say which half was wrong (the server refuses both the same way, and repeating the
 *    server's message is what keeps that true here);
 *  - it does not render the app underneath. A gate you can see through is a gate that leaked the
 *    case name, the source list and the event counts to whoever is standing at it.
 *
 * What it protects and what it does not is stated in Settings -> Security and in HOWTO, not here:
 * the sign-in page was asked to be the password, the PIN and the button, and nothing else.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { api } from '../api/client';
import { Icon } from './icons';

export function useAuthStatus() {
  return useQuery({
    queryKey: ['auth-status'],
    queryFn: api.authStatus,
    staleTime: 30_000,
    retry: false,
  });
}

export function LoginGate({ children }: { children: ReactNode }) {
  const status = useAuthStatus();
  const qc = useQueryClient();
  const [password, setPassword] = useState('');
  const [pin, setPin] = useState('');
  const pwRef = useRef<HTMLInputElement>(null);

  const login = useMutation({
    mutationFn: () => api.login(password, pin),
    onSuccess: () => {
      setPassword('');
      setPin('');
      // Everything fetched while signed out answered 401. Drop the lot rather than reasoning about
      // which queries are safe to keep.
      void qc.invalidateQueries();
      void qc.refetchQueries({ queryKey: ['auth-status'] });
    },
  });

  useEffect(() => { if (status.data?.enabled && !status.data.authenticated) pwRef.current?.focus(); },
    [status.data?.enabled, status.data?.authenticated]);

  // While the status is unknown, render nothing rather than the app: a flash of the case list before
  // the gate appears is the same disclosure the gate exists to prevent.
  if (status.isLoading) return <div className="login" aria-busy="true" />;
  if (!status.data || !status.data.enabled || status.data.authenticated) return <>{children}</>;

  const min = status.data.minPassword ?? 8;
  const minPin = status.data.minPin ?? 4;
  const ready = password.length >= min && pin.length >= minPin;

  return (
    <div className="login">
      <form
        className="login__card"
        onSubmit={(e) => { e.preventDefault(); if (ready && !login.isPending) login.mutate(); }}
      >
        <div className="login__brand">IRIS</div>
        <div className="login__sub">Sign in to this workspace</div>

        <label className="field">
          <span className="field__label">Password</span>
          <input ref={pwRef} className="input" type="password" autoComplete="current-password"
            value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>

        <label className="field">
          <span className="field__label">PIN</span>
          <input className="input" type="password" inputMode="numeric" autoComplete="one-time-code"
            value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))} />
        </label>

        {login.isError && (
          <div className="login__err" role="alert">
            <Icon.Warn />
            <span>{(login.error as Error).message}</span>
          </div>
        )}

        <button className="btn btn--accent login__go" type="submit" disabled={!ready || login.isPending}>
          {login.isPending && <span className="btn__spinner" />}Sign in
        </button>
      </form>
    </div>
  );
}
