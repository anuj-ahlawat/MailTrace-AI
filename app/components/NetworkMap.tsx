'use client';
import { useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
export type GeoPoint = { ip: string; latitude: number; longitude: number; city?: string; country?: string; accuracy_radius_km?: number; asn?: number; organization?: string };
export default function NetworkMap({ points, emptyReason }: { points: GeoPoint[]; emptyReason?: string }) {
  const [tilesUnavailable, setTilesUnavailable] = useState(false);
  if (!points.length) return <div className="soc-empty">{emptyReason || 'No coordinates were recorded for this analysis. Review the observed IPs and GeoIP lookup status; a message without a public IP cannot be placed on the map.'}</div>;
  return <>
    {tilesUnavailable && <p role="status" className="soc-note">Map background unavailable. GeoIP markers and location details are still available. <button type="button" onClick={() => setTilesUnavailable(false)}>Retry map background</button></p>}
    <div style={{ height: 420 }}>
      <MapContainer key={points.map(p => `${p.ip}:${p.latitude}:${p.longitude}`).join('|')} center={points.length===1?[points[0].latitude, points[0].longitude]:undefined} zoom={3}
        bounds={points.length>1?points.map(p => [p.latitude,p.longitude] as [number,number]):undefined}
        boundsOptions={{padding:[24,24],maxZoom:6}} scrollWheelZoom={false}>
        {!tilesUnavailable && <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors'
          url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
          // OSM requires a Referer. Override no-referrer for tiles only, sharing
          // just the app origin, never an investigation path or query string.
          referrerPolicy="strict-origin"
          eventHandlers={{ tileerror: () => setTilesUnavailable(true) }}
        />}
        {points.map(p => <CircleMarker key={p.ip} center={[p.latitude,p.longitude]} radius={8}><Popup><strong>{p.ip}</strong><p>{p.city || 'Unknown'}, {p.country || 'Unknown'}</p><p>Network location, not human attribution.</p><p>Accuracy radius: {p.accuracy_radius_km ?? 'Unknown'} km</p></Popup></CircleMarker>)}
      </MapContainer>
    </div>
  </>;
}
