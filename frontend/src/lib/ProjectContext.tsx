"use client";
import { createContext, useContext, useEffect, useState, ReactNode } from "react";

type Ctx = { projectId: number | null; setProjectId: (id: number | null) => void };
const ProjectCtx = createContext<Ctx>({ projectId: null, setProjectId: () => {} });

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [projectId, setState] = useState<number | null>(null);

  useEffect(() => {
    const v = localStorage.getItem("vapt_project");
    if (v) setState(Number(v));
  }, []);

  const setProjectId = (id: number | null) => {
    setState(id);
    if (id == null) localStorage.removeItem("vapt_project");
    else localStorage.setItem("vapt_project", String(id));
  };

  return <ProjectCtx.Provider value={{ projectId, setProjectId }}>{children}</ProjectCtx.Provider>;
}

export const useProject = () => useContext(ProjectCtx);
