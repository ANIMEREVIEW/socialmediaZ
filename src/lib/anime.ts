// Free anime API integration using Jikan API (MyAnimeList unofficial API)
const JIKAN_BASE_URL = 'https://api.jikan.moe/v4';

export interface Anime {
  mal_id: number;
  title: string;
  title_english?: string;
  title_japanese?: string;
  images: {
    jpg: {
      image_url: string;
      small_image_url: string;
      large_image_url: string;
    };
  };
  synopsis?: string;
  score?: number;
  episodes?: number;
  status?: string;
  aired?: {
    from?: string;
    to?: string;
  };
  genres?: Array<{
    mal_id: number;
    name: string;
  }>;
  studios?: Array<{
    mal_id: number;
    name: string;
  }>;
}

export const animeService = {
  async searchAnime(query: string, limit: number = 10): Promise<Anime[]> {
    try {
      const response = await fetch(
        `${JIKAN_BASE_URL}/anime?q=${encodeURIComponent(query)}&limit=${limit}&order_by=popularity&sort=asc`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch anime');
      }
      
      const data = await response.json();
      return data.data || [];
    } catch (error) {
      console.error('Error searching anime:', error);
      return [];
    }
  },

  async getTopAnime(limit: number = 25): Promise<Anime[]> {
    try {
      const response = await fetch(
        `${JIKAN_BASE_URL}/top/anime?limit=${limit}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch top anime');
      }
      
      const data = await response.json();
      return data.data || [];
    } catch (error) {
      console.error('Error fetching top anime:', error);
      return [];
    }
  },

  async getAnimeById(id: number): Promise<Anime | null> {
    try {
      const response = await fetch(`${JIKAN_BASE_URL}/anime/${id}`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch anime details');
      }
      
      const data = await response.json();
      return data.data || null;
    } catch (error) {
      console.error('Error fetching anime details:', error);
      return null;
    }
  },

  async getRandomAnime(): Promise<Anime | null> {
    try {
      const response = await fetch(`${JIKAN_BASE_URL}/random/anime`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch random anime');
      }
      
      const data = await response.json();
      return data.data || null;
    } catch (error) {
      console.error('Error fetching random anime:', error);
      return null;
    }
  }
};