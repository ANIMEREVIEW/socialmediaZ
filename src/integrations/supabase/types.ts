export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instanciate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "12.2.3 (519615d)"
  }
  public: {
    Tables: {
      admin_keys: {
        Row: {
          created_at: string | null
          id: string
          is_used: boolean | null
          key_code: string
          used_at: string | null
          used_by: string | null
        }
        Insert: {
          created_at?: string | null
          id?: string
          is_used?: boolean | null
          key_code: string
          used_at?: string | null
          used_by?: string | null
        }
        Update: {
          created_at?: string | null
          id?: string
          is_used?: boolean | null
          key_code?: string
          used_at?: string | null
          used_by?: string | null
        }
        Relationships: []
      }
      anime_subscriptions: {
        Row: {
          anime_id: string
          anime_title: string
          created_at: string | null
          id: string
          user_id: string
        }
        Insert: {
          anime_id: string
          anime_title: string
          created_at?: string | null
          id?: string
          user_id: string
        }
        Update: {
          anime_id?: string
          anime_title?: string
          created_at?: string | null
          id?: string
          user_id?: string
        }
        Relationships: []
      }
      comments: {
        Row: {
          content: string
          created_at: string | null
          id: string
          like_count: number | null
          post_id: string | null
          updated_at: string | null
          user_avatar: string | null
          user_id: string
          username: string
        }
        Insert: {
          content: string
          created_at?: string | null
          id?: string
          like_count?: number | null
          post_id?: string | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id: string
          username: string
        }
        Update: {
          content?: string
          created_at?: string | null
          id?: string
          like_count?: number | null
          post_id?: string | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id?: string
          username?: string
        }
        Relationships: [
          {
            foreignKeyName: "comments_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "posts"
            referencedColumns: ["id"]
          },
        ]
      }
      community_comments: {
        Row: {
          content: string
          created_at: string | null
          id: string
          likes: number | null
          parent_id: string | null
          post_id: string | null
          user_avatar: string | null
          user_id: string
          username: string
        }
        Insert: {
          content: string
          created_at?: string | null
          id?: string
          likes?: number | null
          parent_id?: string | null
          post_id?: string | null
          user_avatar?: string | null
          user_id: string
          username: string
        }
        Update: {
          content?: string
          created_at?: string | null
          id?: string
          likes?: number | null
          parent_id?: string | null
          post_id?: string | null
          user_avatar?: string | null
          user_id?: string
          username?: string
        }
        Relationships: [
          {
            foreignKeyName: "community_comments_parent_id_fkey"
            columns: ["parent_id"]
            isOneToOne: false
            referencedRelation: "community_comments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "community_comments_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "community_posts"
            referencedColumns: ["id"]
          },
        ]
      }
      community_posts: {
        Row: {
          category: string
          content: string
          created_at: string | null
          dislikes: number | null
          id: string
          image_url: string | null
          likes: number | null
          link_title: string | null
          link_url: string | null
          status: string | null
          updated_at: string | null
          user_avatar: string | null
          user_id: string
          username: string
        }
        Insert: {
          category?: string
          content: string
          created_at?: string | null
          dislikes?: number | null
          id?: string
          image_url?: string | null
          likes?: number | null
          link_title?: string | null
          link_url?: string | null
          status?: string | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id: string
          username: string
        }
        Update: {
          category?: string
          content?: string
          created_at?: string | null
          dislikes?: number | null
          id?: string
          image_url?: string | null
          likes?: number | null
          link_title?: string | null
          link_url?: string | null
          status?: string | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id?: string
          username?: string
        }
        Relationships: []
      }
      community_reactions: {
        Row: {
          comment_id: string | null
          created_at: string | null
          id: string
          post_id: string | null
          reaction_type: string
          user_id: string
        }
        Insert: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          reaction_type: string
          user_id: string
        }
        Update: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          reaction_type?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "community_reactions_comment_id_fkey"
            columns: ["comment_id"]
            isOneToOne: false
            referencedRelation: "community_comments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "community_reactions_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "community_posts"
            referencedColumns: ["id"]
          },
        ]
      }
      community_reports: {
        Row: {
          comment_id: string | null
          created_at: string | null
          id: string
          post_id: string | null
          reason: string
          reporter_user_id: string
          status: string | null
        }
        Insert: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          reason: string
          reporter_user_id: string
          status?: string | null
        }
        Update: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          reason?: string
          reporter_user_id?: string
          status?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "community_reports_comment_id_fkey"
            columns: ["comment_id"]
            isOneToOne: false
            referencedRelation: "community_comments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "community_reports_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "community_posts"
            referencedColumns: ["id"]
          },
        ]
      }
      likes: {
        Row: {
          comment_id: string | null
          created_at: string | null
          id: string
          post_id: string | null
          user_id: string
        }
        Insert: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          user_id: string
        }
        Update: {
          comment_id?: string | null
          created_at?: string | null
          id?: string
          post_id?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "likes_comment_id_fkey"
            columns: ["comment_id"]
            isOneToOne: false
            referencedRelation: "comments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "likes_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "posts"
            referencedColumns: ["id"]
          },
        ]
      }
      notifications: {
        Row: {
          created_at: string | null
          id: string
          is_read: boolean | null
          message: string
          post_id: string | null
          title: string
          type: string
          user_id: string
        }
        Insert: {
          created_at?: string | null
          id?: string
          is_read?: boolean | null
          message: string
          post_id?: string | null
          title: string
          type: string
          user_id: string
        }
        Update: {
          created_at?: string | null
          id?: string
          is_read?: boolean | null
          message?: string
          post_id?: string | null
          title?: string
          type?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "notifications_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "posts"
            referencedColumns: ["id"]
          },
        ]
      }
      posts: {
        Row: {
          anime_id: string | null
          anime_image: string | null
          anime_title: string | null
          comment_count: number | null
          content: string
          created_at: string | null
          id: string
          like_count: number | null
          link_title: string | null
          link_url: string | null
          media_url: string | null
          original_post_id: string | null
          post_type: Database["public"]["Enums"]["post_type"] | null
          retweet_count: number | null
          status: Database["public"]["Enums"]["post_status"] | null
          updated_at: string | null
          user_avatar: string | null
          user_id: string
          username: string
        }
        Insert: {
          anime_id?: string | null
          anime_image?: string | null
          anime_title?: string | null
          comment_count?: number | null
          content: string
          created_at?: string | null
          id?: string
          like_count?: number | null
          link_title?: string | null
          link_url?: string | null
          media_url?: string | null
          original_post_id?: string | null
          post_type?: Database["public"]["Enums"]["post_type"] | null
          retweet_count?: number | null
          status?: Database["public"]["Enums"]["post_status"] | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id: string
          username: string
        }
        Update: {
          anime_id?: string | null
          anime_image?: string | null
          anime_title?: string | null
          comment_count?: number | null
          content?: string
          created_at?: string | null
          id?: string
          like_count?: number | null
          link_title?: string | null
          link_url?: string | null
          media_url?: string | null
          original_post_id?: string | null
          post_type?: Database["public"]["Enums"]["post_type"] | null
          retweet_count?: number | null
          status?: Database["public"]["Enums"]["post_status"] | null
          updated_at?: string | null
          user_avatar?: string | null
          user_id?: string
          username?: string
        }
        Relationships: [
          {
            foreignKeyName: "posts_original_post_id_fkey"
            columns: ["original_post_id"]
            isOneToOne: false
            referencedRelation: "posts"
            referencedColumns: ["id"]
          },
        ]
      }
      retweets: {
        Row: {
          created_at: string | null
          id: string
          post_id: string | null
          user_id: string
        }
        Insert: {
          created_at?: string | null
          id?: string
          post_id?: string | null
          user_id: string
        }
        Update: {
          created_at?: string | null
          id?: string
          post_id?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "retweets_post_id_fkey"
            columns: ["post_id"]
            isOneToOne: false
            referencedRelation: "posts"
            referencedColumns: ["id"]
          },
        ]
      }
      user_favorites: {
        Row: {
          added_at: string | null
          id: string
          movie_id: string
          movie_poster: string | null
          movie_title: string
          user_id: string
        }
        Insert: {
          added_at?: string | null
          id?: string
          movie_id: string
          movie_poster?: string | null
          movie_title: string
          user_id: string
        }
        Update: {
          added_at?: string | null
          id?: string
          movie_id?: string
          movie_poster?: string | null
          movie_title?: string
          user_id?: string
        }
        Relationships: []
      }
      user_movie_ratings: {
        Row: {
          id: string
          movie_id: string
          rated_at: string | null
          rating: number
          user_id: string
        }
        Insert: {
          id?: string
          movie_id: string
          rated_at?: string | null
          rating: number
          user_id: string
        }
        Update: {
          id?: string
          movie_id?: string
          rated_at?: string | null
          rating?: number
          user_id?: string
        }
        Relationships: []
      }
      user_profiles: {
        Row: {
          avatar_url: string | null
          bio: string | null
          created_at: string | null
          follower_count: number | null
          following_count: number | null
          id: string
          is_admin: boolean | null
          join_date: string | null
          profile_picture: string | null
          updated_at: string | null
          user_id: string
          username: string
        }
        Insert: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string | null
          follower_count?: number | null
          following_count?: number | null
          id?: string
          is_admin?: boolean | null
          join_date?: string | null
          profile_picture?: string | null
          updated_at?: string | null
          user_id: string
          username: string
        }
        Update: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string | null
          follower_count?: number | null
          following_count?: number | null
          id?: string
          is_admin?: boolean | null
          join_date?: string | null
          profile_picture?: string | null
          updated_at?: string | null
          user_id?: string
          username?: string
        }
        Relationships: []
      }
      user_watch_history: {
        Row: {
          duration: number | null
          id: string
          movie_id: string
          movie_poster: string | null
          movie_title: string
          progress: number | null
          user_id: string
          watched_at: string | null
        }
        Insert: {
          duration?: number | null
          id?: string
          movie_id: string
          movie_poster?: string | null
          movie_title: string
          progress?: number | null
          user_id: string
          watched_at?: string | null
        }
        Update: {
          duration?: number | null
          id?: string
          movie_id?: string
          movie_poster?: string | null
          movie_title?: string
          progress?: number | null
          user_id?: string
          watched_at?: string | null
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      set_config: {
        Args: {
          setting_name: string
          setting_value: string
          is_local?: boolean
        }
        Returns: string
      }
    }
    Enums: {
      post_status: "pending" | "approved" | "rejected"
      post_type: "text" | "image" | "gif" | "link" | "retweet"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      post_status: ["pending", "approved", "rejected"],
      post_type: ["text", "image", "gif", "link", "retweet"],
    },
  },
} as const
