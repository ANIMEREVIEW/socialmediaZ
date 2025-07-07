import { useState, useEffect } from 'react';
import { Session } from '@supabase/supabase-js';
import { authService, AuthUser } from '@/lib/auth';

export const useAuth = () => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    const initializeAuth = async () => {
      try {
        // Get initial session
        const { data: { session: initialSession } } = await authService.getSession();
        
        if (mounted) {
          setSession(initialSession);
          
          if (initialSession?.user) {
            const authUser = await authService.getCurrentUser();
            setUser(authUser);
          }
          
          setLoading(false);
        }

        // Set up auth state listener
        const { data: { subscription } } = authService.onAuthStateChange(
          async (session, user) => {
            if (mounted) {
              setSession(session);
              setUser(user);
              setLoading(false);
            }
          }
        );

        return () => {
          subscription.unsubscribe();
        };
      } catch (error) {
        console.error('Auth initialization error:', error);
        if (mounted) {
          setLoading(false);
        }
      }
    };

    initializeAuth();

    return () => {
      mounted = false;
    };
  }, []);

  const signUp = async (email: string, password: string, username: string) => {
    setLoading(true);
    try {
      const result = await authService.signUp(email, password, username);
      return result;
    } catch (error) {
      console.error('Sign up error:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signIn = async (email: string, password: string) => {
    setLoading(true);
    try {
      const result = await authService.signIn(email, password);
      return result;
    } catch (error) {
      console.error('Sign in error:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signOut = async () => {
    setLoading(true);
    try {
      const result = await authService.signOut();
      setUser(null);
      setSession(null);
      return result;
    } catch (error) {
      console.error('Sign out error:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  return {
    user,
    session,
    loading,
    signUp,
    signIn,
    signOut,
    isAdmin: user?.profile?.is_admin === true
  };
};