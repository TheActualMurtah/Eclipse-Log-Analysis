import { useRef, useState } from 'react'

interface Props {
  onUpload: (file: File) => void
  loading: boolean
}

export default function FileUpload({ onUpload, loading }: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function handleFile(file: File) {
    if (file) onUpload(file)
  }

  return (
    <div
      className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors
        ${dragging ? 'border-violet-400 bg-violet-950/30' : 'border-slate-600 hover:border-slate-400'}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={e => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={e => {
        e.preventDefault()
        setDragging(false)
        const file = e.dataTransfer.files[0]
        if (file) handleFile(file)
      }}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept=".log,.txt"
        onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f) }}
      />
      {loading ? (
        <p className="text-slate-300 text-sm animate-pulse">Analyzing log file...</p>
      ) : (
        <>
          <p className="text-slate-300 font-medium">Drop a log file here or click to browse</p>
          <p className="text-slate-500 text-sm mt-1">.log or .txt</p>
        </>
      )}
    </div>
  )
}
