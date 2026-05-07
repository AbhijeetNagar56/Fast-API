import { useState, useEffect } from 'react';
import axiosInstance from '../api/axios';
import { ArrowLeft } from "lucide-react";
import { Link } from "react-router";

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/bmp",
]);

export default function UploadReport() {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState('');
  const [files, setFiles] = useState([]);
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("lab");
  const [visibility, setVisibility] = useState("private");
  const [previewFile, setPreviewFile] = useState(null);
  const [previewType, setPreviewType] = useState(null);

  const API_URL = '/home';

  const fetchFiles = async () => {
    try {
      const res = await axiosInstance.get(`${API_URL}/files`);
      setFiles(res.data);
    } catch (error) {
      console.error(error);
      setFiles([]);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleFileChange = (e) => {
    const selected = e.target.files?.[0];
    if (!selected) return;

    if (!ALLOWED_MIME_TYPES.has(selected.type)) {
      setMessage("Only PDF and image files are allowed");
      setFile(null);
      return;
    }

    if (selected.size > MAX_FILE_SIZE_BYTES) {
      setMessage("File size must be 5MB or less");
      setFile(null);
      return;
    }

    setMessage("");
    setFile(selected);
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a PDF/image file first");
      return;
    }
    if (!title.trim()) {
      setMessage("Please enter report title");
      return;
    }
    if (!category) {
      setMessage("Please select report category");
      return;
    }

    const formData = new FormData();
    formData.append('report', file);
    formData.append("title", title.trim());
    formData.append("category", category);
    formData.append("visibility", visibility);
    formData.append("uploadedBy", "patient");

    try {
      const res = await axiosInstance.post(
        `${API_URL}/upload`,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      setMessage(res.data.msg);
      setFile(null);
      setTitle("");
      setCategory("lab");
      setVisibility("private");
      fetchFiles();
    } catch (error) {
      console.error(error);
      setMessage(error.response?.data?.msg || 'Upload failed');
    }
  };

  const handleDelete = async (id) => {
    try {
      await axiosInstance.delete(`${API_URL}/file/${id}`);
      setMessage('File deleted');
      fetchFiles();
    } catch (error) {
      console.error(error);
      setMessage('Delete failed');
    }
  };

  const handlePreview = async (id) => {
    try {
      const res = await axiosInstance.get(
        `${API_URL}/file/${id}`,
        { responseType: 'blob' }
      );

      const blob = new Blob([res.data], { type: res.data.type });
      const url = URL.createObjectURL(blob);

      if (blob.type.startsWith("image/")) {
        setPreviewType('image');
      } else if (blob.type === "application/pdf") {
        setPreviewType('pdf');
      } else {
        setPreviewType('other');
      }

      setPreviewFile(url);
    } catch (err) {
      console.error('Preview error:', err);
    }
  };

  return (
    <>
      <div className="card bg-base-200 p-4 shadow-md w-[70%] justify-self-center my-10">
        <Link to="/services" className="text-gray-500 hover:text-gray-700">
          <ArrowLeft size={24} />
        </Link>
        <h2 className="text-xl font-semibold mt-4">Upload Medical Report</h2>
        <p className='text-red-400 mb-4'>Allowed: PDF/images, max size 5MB</p>
        <input
          onChange={handleFileChange}
          type="file"
          className="file-input file-input-bordered w-full"
          accept=".pdf,image/*"
        />
        <input
          type="text"
          placeholder="Report title"
          className="input input-bordered w-full mt-3"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
          <select
            className="select select-bordered w-full"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          >
            <option value="lab">Lab</option>
            <option value="prescription">Prescription</option>
            <option value="scan">Scan</option>
            <option value="discharge">Discharge</option>
            <option value="other">Other</option>
          </select>
          <select
            className="select select-bordered w-full"
            value={visibility}
            onChange={(e) => setVisibility(e.target.value)}
          >
            <option value="private">Private</option>
            <option value="doctor">Doctor</option>
            <option value="public">Public</option>
          </select>
        </div>

        <button className="btn btn-primary mt-4" onClick={handleUpload}>
          Upload
        </button>

        {message && <p className="mt-2 text-green-600">{message}</p>}

        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2">Uploaded Files</h3>

          {files.length > 0 ? (
            <ul className="list-disc pl-5">
              {files.map((f) => (
                <li key={f._id} className="mb-4">
                  <div className="flex items-center gap-4">
                    <button
                      className="text-blue-500 underline"
                      onClick={() => handlePreview(f._id)}
                    >
                      Preview
                    </button>

                    <span>
                      <strong>{f.title}</strong> ({f.category}) - {f.visibility}
                      {f.originalFileName ? ` - ${f.originalFileName}` : ""}
                    </span>

                    <button
                      className="btn btn-error btn-sm"
                      onClick={() => handleDelete(f._id)}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p>No files uploaded yet.</p>
          )}
        </div>
      </div>

      {/* Preview Modal */}
      {previewFile && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-4 max-w-4xl w-full h-[80vh] relative">
            <button
              className="absolute top-2 right-2 btn btn-sm btn-error"
              onClick={() => {
                URL.revokeObjectURL(previewFile);
                setPreviewFile(null);
                setPreviewType(null);
              }}
            >
              Close
            </button>

            {previewType === 'image' && (
              <img
                src={previewFile}
                alt="Preview"
                className="w-full h-full object-contain"
              />
            )}

            {previewType === 'pdf' && (
              <iframe
                src={previewFile}
                title="PDF Preview"
                className="w-full h-full"
              />
            )}

            {previewType === 'other' && (
              <p className="text-center mt-10">
                File preview not supported.{' '}
                <a
                  href={previewFile}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-500 underline"
                >
                  Download instead
                </a>
              </p>
            )}
          </div>
        </div>
      )}

    </>
  );
}
