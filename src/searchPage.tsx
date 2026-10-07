import { useState } from "react";

const API_BASE = process.env.NODE_ENV === 'development'
  ? `http://${window.location.hostname}:5000`
  : '';

interface SearchResult {
  valid: boolean;
  name?: string;
  ipfs?: string;
}

export default function SearchPage() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<SearchResult | null>(null);
  const [status, setStatus] = useState("");

  const searchCertificate = async () => {
    try {
      setStatus("🔍 Searching...");
      setResult(null);

      const res = await fetch(`${API_BASE}/api/verify/${hash}`);
      const data = await res.json();

      if (data.valid) {
        setResult({
          valid: true,
          name: data.name,
          ipfs: data.ipfs
        });
        setStatus("✅ Certificate Found");
      } else {
        setResult({ valid: false });
        setStatus("❌ Certificate Not Found");
      }
    } catch (err) {
      console.error(err);
      setStatus("❌ Error fetching certificate");
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 p-8 flex justify-center items-center">
      <div className="bg-white shadow-xl rounded-2xl p-6 w-full max-w-xl">
        <h1 className="text-2xl font-bold mb-4 text-center">
          🎓 Certificate Search
        </h1>

        <input
          type="text"
          placeholder="Enter Certificate Hash"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          className="w-full p-2 border rounded-lg mb-4"
        />

        <button
          onClick={searchCertificate}
          className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700"
        >
          Search Certificate
        </button>

        <p className="mt-4 text-center">{status}</p>

        {result && result.valid && (
          <div className="mt-6 p-4 border rounded-lg bg-green-50">
            <p>
              <strong>✅ Name:</strong> {result.name}
            </p>
            <a
              href={`https://ipfs.io/ipfs/${result.ipfs}`}
              target="_blank"
              rel="noreferrer"
              className="text-blue-600 underline"
            >
              🔗 View Certificate
            </a>
          </div>
        )}

        {result && !result.valid && (
          <div className="mt-6 p-4 border rounded-lg bg-red-50">
            ❌ No certificate found with this hash
          </div>
        )}
      </div>
    </div>
  );
}