// User following system service
import { supabase } from '@/integrations/supabase/client';

export interface UserProfile {
  user_id: string;
  username: string;
  avatar_url?: string;
  bio?: string;
  follower_count: number;
  following_count: number;
  is_admin?: boolean;
}

export const followsService = {
  async followUser(followerId: string, followingId: string): Promise<void> {
    const { error } = await supabase
      .from('user_follows')
      .insert({
        follower_id: followerId,
        following_id: followingId
      });

    if (error) throw error;
  },

  async unfollowUser(followerId: string, followingId: string): Promise<void> {
    const { error } = await supabase
      .from('user_follows')
      .delete()
      .eq('follower_id', followerId)
      .eq('following_id', followingId);

    if (error) throw error;
  },

  async isFollowing(followerId: string, followingId: string): Promise<boolean> {
    const { data, error } = await supabase
      .from('user_follows')
      .select('id')
      .eq('follower_id', followerId)
      .eq('following_id', followingId)
      .maybeSingle();

    if (error) throw error;
    return !!data;
  },

  async getFollowers(userId: string, limit: number = 50): Promise<UserProfile[]> {
    const { data, error } = await supabase
      .from('user_follows')
      .select(`
        follower_id,
        user_profiles!user_follows_follower_id_fkey (
          user_id,
          username,
          avatar_url,
          bio,
          follower_count,
          following_count,
          is_admin
        )
      `)
      .eq('following_id', userId)
      .limit(limit);

    if (error) throw error;
    return data?.map(item => item.user_profiles).filter(Boolean) || [];
  },

  async getFollowing(userId: string, limit: number = 50): Promise<UserProfile[]> {
    const { data, error } = await supabase
      .from('user_follows')
      .select(`
        following_id,
        user_profiles!user_follows_following_id_fkey (
          user_id,
          username,
          avatar_url,
          bio,
          follower_count,
          following_count,
          is_admin
        )
      `)
      .eq('follower_id', userId)
      .limit(limit);

    if (error) throw error;
    return data?.map(item => item.user_profiles).filter(Boolean) || [];
  },

  async searchUsers(query: string, limit: number = 20): Promise<UserProfile[]> {
    const { data, error } = await supabase
      .from('user_profiles')
      .select('*')
      .ilike('username', `%${query}%`)
      .order('follower_count', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return data || [];
  },

  async getSuggestedUsers(userId: string, limit: number = 10): Promise<UserProfile[]> {
    // Get users that the current user is not following, ordered by follower count
    const { data, error } = await supabase
      .from('user_profiles')
      .select('*')
      .neq('user_id', userId)
      .not('user_id', 'in', `(
        SELECT following_id 
        FROM user_follows 
        WHERE follower_id = '${userId}'
      )`)
      .order('follower_count', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return data || [];
  }
};