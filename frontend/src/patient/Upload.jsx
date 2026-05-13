import { useState, useEffect } from 'react';
import axiosInstance from '../api/axios';
import { 
  ArrowLeft, Upload, FileText, Trash2, 
  Eye, FileUp, AlertCircle, Shield, 
  Tag, Info 
} from "lucide-react";
import { Link } from "react-router"; // Adjust to "react-router-dom" if using older version

export default function UploadReport() {
  // --- Form State ---
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('LAB');
  const [visibility, setVisibility] = useState('private');
  
  // --- UI & Data State ---
  const [message, setMessage] = useState(null);
  const [files, setFiles] = useState([]);
  const [previewFile, setPreviewFile] = useState(null);
  const [previewType, setPreviewType] = useState(null);
  const [isUploading, setIsUploading] = useState(false);

  const API_URL = '/home';

  const fetchFiles = async () => {
    try {
      const res = await axiosInstance.get(`${API_URL}/files`);
      setFiles(res.data);
    } catch (error) {
      console.error("Fetch error:", error);
      setFiles([]);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) setFile(selectedFile);
  };

  const handleUpload = async () => {
    if (!file || !title) {
      setMessage({ text: 'Please provide a title and select a file', type: 'error' });
      return;
    }

    setIsUploading(true);
    const formData = new FormData();
    formData.append('report', file);
    formData.append('title', title);
    formData.append('category', category);
    formData.append('visibility', visibility);

    try {
      const res = await axiosInstance.post(`${API_URL}/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      setMessage({ text: res.data.msg || 'Upload successful!', type: 'success' });
      
      // Reset Form
      setFile(null);
      setTitle('');
      setCategory('LAB');
      setVisibility('private');
      
      fetchFiles();
    } catch (error) {
      console.error("Upload error:", error);
      setMessage({ text: 'Upload failed. Please try again.', type: 'error' });
    } finally {
      setIsUploading(false);
      setTimeout(() => setMessage(null), 4000);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this medical record permanently?")) return;
    try {
      await axiosInstance.delete(`${API_URL}/file/${id}`);
      setMessage({ text: 'File deleted', type: 'success' });
      fetchFiles();
    } catch (error) {
      setMessage({ text: 'Delete failed', type: 'error' });
    }
  };

  const handlePreview = async (id, filename) => {
    try {
      const res = await axiosInstance.get(`${API_URL}/file/${id}`, { responseType: 'blob' });
      const blob = new Blob([res.data], { type: res.data.type });
      const url = URL.createObjectURL(blob);

      if (/\.(jpg|jpeg|png|gif|webp)$/i.test(filename)) setPreviewType('image');
      else if (/\.pdf$/i.test(filename)) setPreviewType('pdf');
      else setPreviewType('other');

      setPreviewFile(url);
    } catch (err) {
      console.error('Preview error:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 py-8 px-4">
      <div className="max-w-6xl mx-auto">
        
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4">
          <div className="flex items-center gap-4">
            <Link to="/" className="btn btn-circle btn-ghost bg-white shadow-sm hover:text-primary">
              <ArrowLeft size={20} />
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">Medical Records</h1>
              <p className="text-sm text-slate-500">Securely store and manage your health reports</p>
            </div>
          </div>
          {message && (
            <div className={`alert ${message.type === 'success' ? 'alert-success' : 'alert-error'} shadow-lg w-auto py-2`}>
              <Info size={18} />
              <span className="text-sm">{message.text}</span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* LEFT: Upload Form Card */}
          <div className="lg:col-span-4">
            <div className="card bg-white shadow-xl border border-slate-100 overflow-visible sticky top-8">
              <div className="card-body p-6">
                <div className="flex items-center gap-2 mb-6 text-primary">
                  <div className="p-2 bg-blue-50 rounded-lg">
                    <FileUp size={20} />
                  </div>
                  <h2 className="card-title text-lg font-bold">Upload Report</h2>
                </div>

                <div className="space-y-5">
                  {/* Title Input */}
                  <div className="form-control">
                    <label className="label pt-0">
                      <span className="label-text font-semibold flex items-center gap-2">
                        Title <span className="text-error">*</span>
                      </span>
                    </label>
                    <input 
                      type="text" 
                      placeholder="e.g., Annual Checkup 2024" 
                      className="input input-bordered w-full focus:input-primary"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                    />
                  </div>

                  {/* Category Select */}
                  <div className="form-control">
                    <label className="label pt-0">
                      <span className="label-text font-semibold flex items-center gap-2">
                        <Tag size={14} /> Category
                      </span>
                    </label>
                    <select 
                      className="select select-bordered w-full"
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                    >
                      <option value="LAB">Lab Report</option>
                      <option value="PRESCRIPTION">Prescription</option>
                      <option value="SCAN">Scan (MRI, X-Ray)</option>
                      <option value="DISCHARGE">Discharge Summary</option>
                      <option value="OTHER">Other</option>
                    </select>
                  </div>

                  {/* Visibility Select */}
                  <div className="form-control">
                    <label className="label pt-0">
                      <span className="label-text font-semibold flex items-center gap-2">
                        <Shield size={14} /> Privacy
                      </span>
                    </label>
                    <select 
                      className="select select-bordered w-full"
                      value={visibility}
                      onChange={(e) => setVisibility(e.target.value)}
                    >
                      <option value="private">Private (Me Only)</option>
                      <option value="doctor">Visible to Doctor</option>
                    </select>
                  </div>

                  {/* File Dropzone */}
                  <div className={`relative border-2 border-dashed rounded-2xl p-6 transition-all duration-200 group 
                    ${file ? 'border-success bg-green-50/30' : 'border-slate-200 hover:border-primary bg-slate-50'}`}>
                    <input
                      type="file"
                      id="file-upload"
                      className="hidden"
                      onChange={handleFileChange}
                    />
                    <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center justify-center">
                      {file ? (
                        <div className="text-center">
                          <div className="p-3 bg-success/10 text-success rounded-full inline-block mb-2">
                            <FileText size={32} />
                          </div>
                          <p className="text-xs font-bold text-slate-700 truncate max-w-[200px]">{file.name}</p>
                          <p className="text-[10px] text-slate-400">Click to change</p>
                        </div>
                      ) : (
                        <div className="text-center">
                          <Upload className="text-slate-300 group-hover:text-primary mb-2 mx-auto transition-colors" size={32} />
                          <p className="text-xs font-medium text-slate-500 italic">PNG, JPG or PDF supported</p>
                        </div>
                      )}
                    </label>
                  </div>

                  <button 
                    className={`btn btn-primary w-full shadow-md ${isUploading ? 'loading' : ''}`}
                    onClick={handleUpload}
                    disabled={!file || !title || isUploading}
                  >
                    {isUploading ? 'Processing...' : 'Upload Record'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* RIGHT: Records List */}
          <div className="lg:col-span-8">
            <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden min-h-[500px]">
              <div className="p-6 border-b border-slate-50 flex items-center justify-between">
                <h3 className="font-bold text-slate-700 text-lg">Stored Documents</h3>
                <span className="badge badge-ghost font-medium">{files.length} Files</span>
              </div>

              {files.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="table table-zebra w-full">
                    <thead>
                      <tr className="text-slate-400 uppercase text-[11px] tracking-wider">
                        <th>Report Info</th>
                        <th>Category</th>
                        <th>Privacy</th>
                        <th className="text-center">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr key={f._id} className="hover">
                          <td>
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-slate-100 rounded text-slate-500">
                                <FileText size={18} />
                              </div>
                              <div>
                                <div className="font-bold text-sm text-slate-800">{f.title || f.filename}</div>
                                <div className="text-[10px] text-slate-400 italic">Uploaded {new Date(f.createdAt).toLocaleDateString()}</div>
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className="badge badge-sm badge-outline text-slate-500">{f.category}</span>
                          </td>
                          <td>
                            {f.visibility === 'private' ? (
                              <span className="flex items-center gap-1 text-xs text-slate-500"><Shield size={12}/> Private</span>
                            ) : (
                              <span className="flex items-center gap-1 text-xs text-blue-500 font-medium"><Eye size={12}/> Doctor Access</span>
                            )}
                          </td>
                          <td>
                            <div className="flex justify-center gap-2">
                              <button
                                className="btn btn-square btn-sm btn-ghost text-primary"
                                onClick={() => handlePreview(f._id, f.filename)}
                                title="View document"
                              >
                                <Eye size={18} />
                              </button>
                              <button
                                className="btn btn-square btn-sm btn-ghost text-error"
                                onClick={() => handleDelete(f._id)}
                                title="Delete document"
                              >
                                <Trash2 size={18} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-32 text-slate-300">
                  <FileText size={64} strokeWidth={1} className="mb-4 opacity-20" />
                  <p className="text-lg font-medium">No medical reports found</p>
                  <p className="text-sm">Use the form on the left to start uploading.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* --- PREVIEW MODAL --- */}
      {previewFile && (
        <div className="fixed inset-0 bg-slate-900/90 backdrop-blur-md flex items-center justify-center z-[100] p-4 md:p-10">
          <div className="bg-white rounded-3xl shadow-2xl w-full max-w-5xl h-full flex flex-col overflow-hidden">
            <div className="p-4 border-b flex justify-between items-center bg-white">
              <div className="flex items-center gap-2">
                <FileText className="text-primary" size={20} />
                <span className="font-bold text-slate-800 text-sm md:text-base">Record Preview</span>
              </div>
              <button
                className="btn btn-circle btn-sm btn-error btn-outline border-none"
                onClick={() => {
                  URL.revokeObjectURL(previewFile);
                  setPreviewFile(null);
                }}
              >
                ✕
              </button>
            </div>

            <div className="flex-1 bg-slate-100 overflow-auto flex items-center justify-center">
              {previewType === 'image' && (
                <img src={previewFile} alt="Preview" className="max-w-full max-h-full object-contain p-2" />
              )}
              {previewType === 'pdf' && (
                <iframe src={previewFile} className="w-full h-full border-none" title="PDF Preview" />
              )}
              {previewType === 'other' && (
                <div className="text-center p-10">
                   <div className="p-6 bg-white rounded-2xl shadow-sm inline-block">
                    <p className="mb-4 text-slate-600 font-medium">This file format cannot be previewed online.</p>
                    <a href={previewFile} download className="btn btn-primary btn-wide">Download to View</a>
                   </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}