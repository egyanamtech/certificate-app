import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import VerifyResult, { computeStats } from './VerifyResult';
import { ThemeContext, BrandContext } from './App';
import { UNIVERSITY } from './config';

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
        <VerifyResult onBack={jest.fn()} />
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );
}

const subjects = [
  { subject: 'Math', marks: 85, maxMarks: 100, grade: 'A' },
  { subject: 'Physics', marks: 78, maxMarks: 100, grade: 'B' },
];

describe('computeStats', () => {
  test('computes totals and percentage', () => {
    const s = computeStats(subjects);
    expect(s.total).toBe(163);
    expect(s.max).toBe(200);
    expect(s.pct).toBe(82);
  });

  test('flags pass when no F grades or zero marks', () => {
    expect(computeStats(subjects).allPassed).toBe(true);
  });

  test('flags review on F grade', () => {
    const s = computeStats([{ subject: 'x', marks: 40, maxMarks: 100, grade: 'F' }]);
    expect(s.allPassed).toBe(false);
  });

  test('flags review on zero marks', () => {
    const s = computeStats([{ subject: 'x', marks: 0, maxMarks: 100, grade: 'B' }]);
    expect(s.allPassed).toBe(false);
  });
});

test('renders roll number input', () => {
  renderPage();
  expect(screen.getByPlaceholderText(/Roll Number/)).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/Semester \(optional\)/)).toBeInTheDocument();
});

test('fetches results by roll number and shows marksheet', async () => {
  global.fetch.mockResolvedValueOnce({
    json: () => Promise.resolve([
      { id: '1', rollNumber: '2024001', name: 'John Doe', department: 'CS', semester: 'Sem 1', subjects },
    ]),
  });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText(/Roll Number/), { target: { value: '2024001' } });
  fireEvent.click(screen.getByRole('button', { name: /Search/ }));

  await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument());
  expect(screen.getByText('Math')).toBeInTheDocument();
  expect(screen.getByText('163')).toBeInTheDocument();
  expect(screen.getByText('PASS')).toBeInTheDocument();
});

test('shows not found when no results', async () => {
  global.fetch.mockResolvedValueOnce({ json: () => Promise.resolve([]) });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText(/Roll Number/), { target: { value: 'NOPE' } });
  fireEvent.click(screen.getByRole('button', { name: /Search/ }));

  await waitFor(() => expect(screen.getByText('No Result Found')).toBeInTheDocument());
});

test('raise issue button opens form', () => {
  renderPage();
  fireEvent.click(screen.getByRole('button', { name: /Raise Issue/ }));
  expect(screen.getByText(/Raise an Issue/)).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/Describe the issue/)).toBeInTheDocument();
});

test('submits issue to admin endpoint', async () => {
  global.fetch.mockResolvedValueOnce({ json: () => Promise.resolve({ success: true }) });
  renderPage();
  fireEvent.change(screen.getByPlaceholderText(/Roll Number/), { target: { value: '2024001' } });
  fireEvent.click(screen.getByRole('button', { name: /Raise Issue/ }));
  fireEvent.change(screen.getByPlaceholderText(/Describe the issue/), { target: { value: 'Math marks look wrong' } });
  fireEvent.click(screen.getByRole('button', { name: /Submit Issue/ }));

  await waitFor(() => expect(screen.getByText('Issue submitted to the admin. Thank you!')).toBeInTheDocument());
  expect(global.fetch).toHaveBeenCalledWith(
    expect.stringContaining('/api/issues'),
    expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ rollNumber: '2024001', semester: '', message: 'Math marks look wrong' }),
    })
  );
});

test('alerts when submitting issue without roll number', () => {
  const alertSpy = jest.spyOn(window, 'alert').mockImplementation(() => {});
  renderPage();
  fireEvent.click(screen.getByRole('button', { name: /Raise Issue/ }));
  fireEvent.change(screen.getByPlaceholderText(/Describe the issue/), { target: { value: 'marks wrong' } });
  fireEvent.click(screen.getByRole('button', { name: /Submit Issue/ }));
  expect(alertSpy).toHaveBeenCalledWith('Enter a roll number first');
});