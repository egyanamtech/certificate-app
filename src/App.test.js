import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import { UNIVERSITY } from './config';

beforeEach(() => {
  localStorage.clear();
  window.location.hash = '';
  global.fetch = jest.fn(() =>
    Promise.resolve({ json: () => Promise.resolve({ name: UNIVERSITY.name }) })
  );
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('renders landing page with university branding', async () => {
  render(<App />);
  expect(screen.getByRole('heading', { level: 1, name: UNIVERSITY.name })).toBeInTheDocument();
  expect(screen.getByText(/Blockchain Certificate Issuance/)).toBeInTheDocument();
  expect(screen.getByText(/Verify a Certificate/)).toBeInTheDocument();
  expect(screen.getByText(/Admin Portal/)).toBeInTheDocument();
  await waitFor(() => expect(global.fetch).toHaveBeenCalled());
});

test('shows How It Works and trust sections', async () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: 'How It Works' })).toBeInTheDocument();
  expect(screen.getByText(/no third party/)).toBeInTheDocument();
  await waitFor(() => expect(global.fetch).toHaveBeenCalled());
});

test('navigates to verify page via button', async () => {
  render(<App />);
  fireEvent.click(screen.getByText(/Verify a Certificate/));
  expect(screen.getByRole('heading', { name: 'Verify Certificate' })).toBeInTheDocument();
  expect(window.location.hash).toBe('#verify');
  await waitFor(() => expect(global.fetch).toHaveBeenCalled());
});

test('navigates to admin portal via button', async () => {
  render(<App />);
  fireEvent.click(screen.getByText(/Admin Portal/));
  expect(window.location.hash).toBe('#admin');
  await waitFor(() => expect(global.fetch).toHaveBeenCalled());
});

test('theme toggle flips between dark and light', async () => {
  render(<App />);
  const toggle = screen.getByRole('button', { name: 'Toggle theme' });
  const initial = document.body.className;
  fireEvent.click(toggle);
  await waitFor(() => expect(document.body.className).not.toBe(initial));
  expect(['dark', 'light']).toContain(document.body.className);
});