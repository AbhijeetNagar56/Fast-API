import { useState, useRef, useEffect } from "react";
import axiosInstance from "../api/axios";
import { Send, Bot, User, AlertTriangle, ArrowLeft, Loader2 } from "lucide-react";
import { Link } from "react-router";

export default function AiHealthChatbot() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "ai",
      text: "Hi, I’m your health assistant. Tell me your symptoms and I’ll guide you on what to do next.",
    },
  ]);

  const messagesEndRef = useRef(null);

  // Auto scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;

    const userMessage = { role: "user", text: input };
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const res = await axiosInstance.post("/auth/chat", {
        message: userMessage.text,
      });

      const aiMessage = {
        role: "ai",
        text: res.data.reply,
      };

      setMessages((prev) => [...prev, aiMessage]);
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          role: "ai",
          text: "Sorry, I couldn’t process that right now. Please try again later.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-base-200">
      
      {/* Header */}
      <div className="navbar bg-base-100 shadow-sm px-3 sm:px-6">
        <Link to="/" className="btn btn-ghost btn-circle">
          <ArrowLeft size={22} />
        </Link>
        <div className="flex-1">
          <h1 className="text-lg sm:text-xl font-bold">AI Health Assistant</h1>
        </div>
      </div>

      {/* Disclaimer */}
      <div className="px-3 sm:px-6 mt-2">
        <div className="alert alert-warning text-xs sm:text-sm">
          <AlertTriangle size={16} />
          <span>
            This chatbot gives general guidance only. Always consult a certified doctor.
          </span>
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 overflow-y-auto px-3 sm:px-6 py-4 space-y-2">
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`chat ${
              msg.role === "user" ? "chat-end" : "chat-start"
            }`}
          >
            <div className="chat-image avatar placeholder">
              <div className="bg-neutral text-neutral-content rounded-full w-8">
                {msg.role === "user" ? (
                  <User size={16} className="m-auto" />
                ) : (
                  <Bot size={16} className="m-auto" />
                )}
              </div>
            </div>

            <div className="chat-bubble text-sm sm:text-base">
              {msg.text}
            </div>
          </div>
        ))}

        {loading && (
          <div className="chat chat-start">
            <div className="chat-bubble flex items-center gap-2">
              <Loader2 className="animate-spin" size={16} />
              Typing...
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Area (Sticky Bottom) */}
      <div className="bg-base-100 border-t p-3 sm:p-4">
        <div className="flex gap-2 max-w-4xl mx-auto">
          <input
            type="text"
            placeholder="Describe your symptoms..."
            className="input input-bordered flex-1 text-sm sm:text-base"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && sendMessage()}
          />

          <button
            className="btn btn-primary btn-square"
            onClick={sendMessage}
            disabled={loading || !input.trim()}
          >
            {loading ? (
              <Loader2 className="animate-spin" size={18} />
            ) : (
              <Send size={18} />
            )}
          </button>
        </div>
      </div>
    </div>
  );
}