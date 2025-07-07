import { supabase } from '@/integrations/supabase/client';
import { User, Session } from '@supabase/supabase-js';

export interface AuthUser extends User {
  profile?: {
    username: string;
    avatar_url?: string;
    bio?: string;
    is_admin?: boolean;
  };
}

export const authService = {
  async getSession() {
    return await supabase.auth.getSession();
  },

  async signUp(email: string, password: string, username: string) {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${window.location.origin}/`,
        data: {
          username,
        }
      }
    });

    if (error) throw error;

    // Create user profile
    if (data.user) {
      try {
        // Set user context first
        await supabase.rpc('set_config', { 
          setting_name: 'app.current_user_id', 
          setting_value: data.user.id 
        });

        const { error: profileError } = await supabase.from('user_profiles').insert({
          user_id: data.user.id,
          username,
          avatar_url: '',
          bio: '',
          is_admin: false
        });

        if (profileError) {
          console.error('Error creating profile:', profileError);
        }
      } catch (profileError) {
        console.error('Profile creation failed:', profileError);
      }
    }

    return { data, error: null };
  },

  async signIn(email: string, password: string) {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    return { data, error };
  },

  async signOut() {
    const { error } = await supabase.auth.signOut();
    return { error };
  },

  async getCurrentUser(): Promise<AuthUser | null> {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      
      if (!user) return null;

      // Set the user context
      try {
        await supabase.rpc('set_config', { 
          setting_name: 'app.current_user_id', 
          setting_value: user.id 
        });
      } catch (error) {
        console.error('Error setting user context:', error);
      }

      // Get user profile
      const { data: profile, error: profileError } = await supabase
        .from('user_profiles')
        .select('*')
        .eq('user_id', user.id)
        .maybeSingle();

      if (profileError) {
        console.error('Error fetching profile:', profileError);
      }

      return {
        ...user,
        profile: profile || undefined
      } as AuthUser;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  },

  onAuthStateChange(callback: (session: Session | null, user: AuthUser | null) => void) {
    return supabase.auth.onAuthStateChange(async (event, session) => {
      try {
        let authUser: AuthUser | null = null;
        
        if (session?.user) {
          // Set user context
          try {
            await supabase.rpc('set_config', { 
              setting_name: 'app.current_user_id', 
              setting_value: session.user.id 
            });
          } catch (error) {
            console.error('Error setting user context:', error);
          }

          // Get profile data
          const { data: profile, error: profileError } = await supabase
            .from('user_profiles')
            .select('*')
            .eq('user_id', session.user.id)
            .maybeSingle();

          if (profileError) {
            console.error('Error fetching profile:', profileError);
          }

          authUser = {
            ...session.user,
            profile: profile || undefined
          } as AuthUser;
        }

        callback(session, authUser);
      } catch (error) {
        console.error('Auth state change error:', error);
        callback(session, null);
      }
    });
  }
};