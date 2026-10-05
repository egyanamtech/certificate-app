import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import VerifyPage from './VerifyPage';
import { ThemeContext, BrandContext } from './App';
import { UNIVERSITY } from './config';

const HASH = '97fe27d1c7ccf71d2e8c99959a361eb2ce62f181aa8d6b50b705f2707860af35';
const IPFS = 'QmXyZ123abc';
const toggleTheme = jest.fn();

beforeEach(() => {
  global.fetch = jest.fn();
});

afterEach(() => {
  jest.clearAllMocks();
});

function renderPage() {
  return render(
    <ThemeContext.Provider value={{ theme: 'dark', toggleTheme }}>
      <BrandContext.Provider value={{ brand: UNIVERSITY, setBrand: jest.fn() }}>
        <VerifyPage onBack={jest.fn()} />
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );
}

test('renders header and hash-only input', () => {
  renderPage();
  expect(screen.getByRole('heading', { name: 'Verify Certificate' })).toBeInTheDocument();
  expect(screen.getByPlaceholderText('Enter Certificate Hash')).toBeInTheDocument();
});

test('verifies by hash and shows only the hash value', async () => {
  global.fetch.mockResolvedValueOnce({
    json: () => Promise.resolve({ valid: true, hash: HASH }),
  });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: HASH } });
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));

  await waitFor(() => expect(screen.getAllByText('Certificate Verified').length).toBeGreaterThan(0));
  expect(screen.getByText(HASH)).toBeInTheDocument();
  expect(global.fetch).toHaveBeenCalledWith(
    expect.stringContaining(`/api/verify/${HASH}`)
  );
});

test('shows download certificate link when ipfs hash present', async () => {
  global.fetch.mockResolvedValueOnce({
    json: () => Promise.resolve({ valid: true, hash: HASH, ipfsHash: IPFS }),
  });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: HASH } });
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));

  await waitFor(() => expect(screen.getAllByText('Certificate Verified').length).toBeGreaterThan(0));
  expect(screen.getByText(/Download Certificate/)).toBeInTheDocument();
  expect(screen.getByText(/Download Certificate/).closest('a')).toHaveAttribute(
    'href', `https://ipfs.io/ipfs/${IPFS}`
  );
});

test('hides download link when no ipfs hash', async () => {
  global.fetch.mockResolvedValueOnce({
    json: () => Promise.resolve({ valid: true, hash: HASH }),
  });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: HASH } });
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));

  await waitFor(() => expect(screen.getAllByText('Certificate Verified').length).toBeGreaterThan(0));
  expect(screen.queryByText(/Download Certificate/)).not.toBeInTheDocument();
});

test('does not render name or roll number when verified', async () => {
  global.fetch.mockResolvedValueOnce({
    json: () => Promise.resolve({ valid: true, hash: HASH }),
  });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: HASH } });
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));

  await waitFor(() => expect(screen.getAllByText('Certificate Verified').length).toBeGreaterThan(0));
  expect(screen.queryByText(/Name:/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Roll No:/)).not.toBeInTheDocument();
});

test('shows not found for unknown hash', async () => {
  global.fetch.mockResolvedValueOnce({ json: () => Promise.resolve({ valid: false }) });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: 'deadbeef' } });
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));

  await waitFor(() => expect(screen.getAllByText('Certificate Not Found').length).toBeGreaterThan(0));
});

test('alerts when hash is empty', () => {
  const alertSpy = jest.spyOn(window, 'alert').mockImplementation(() => {});
  renderPage();
  fireEvent.click(screen.getByRole('button', { name: /Verify/ }));
  expect(alertSpy).toHaveBeenCalledWith('Enter a certificate hash');
});

test('verifies on Enter key', async () => {
  global.fetch.mockResolvedValueOnce({ json: () => Promise.resolve({ valid: true, hash: HASH }) });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText('Enter Certificate Hash'), { target: { value: HASH } });
  fireEvent.keyDown(screen.getByPlaceholderText('Enter Certificate Hash'), { key: 'Enter' });
  await waitFor(() => expect(global.fetch).toHaveBeenCalled());
});