import React from "react";
import { View } from "react-native";
import Svg, { Circle, Ellipse, G, Rect } from "react-native-svg";

const DARK = "#141414";

interface Props {
  color: string;
  shape?: string;
  size?: number;
  ring?: boolean;
}

export function BotAvatar({ color, shape = "waddle", size = 48, ring = false }: Props) {
  const inner = ring ? 0.86 : 1;
  const offset = ring ? 3.4 : 0;
  return (
    <View style={{ width: size, height: size }}>
      <Svg width={size} height={size} viewBox="0 0 48 48">
        {ring ? <Circle cx="24" cy="24" r="18" fill="#3a3a3a" /> : null}
        <G transform={`translate(${offset} ${offset}) scale(${inner})`}>{shapeBody(shape, color)}</G>
        <Visor />
      </Svg>
    </View>
  );
}

function Visor() {
  return (
    <>
      <Rect x={13} y={18} width={22} height={12} rx={6} fill={DARK} />
      <Rect x={16} y={20} width={5} height={8} rx={2} fill="#6b6b6b" />
      <Rect x={27} y={20} width={5} height={8} rx={2} fill="#6b6b6b" />
    </>
  );
}

function shapeBody(shape: string, color: string): React.ReactNode {
  switch (shape) {
    case "drop":
      return <Ellipse cx="24" cy="26" rx="14" ry="17" fill={color} />;
    case "square":
      return <Rect x="10" y="10" width="28" height="28" rx="10" fill={color} />;
    case "bean":
      return <Ellipse cx="24" cy="26" rx="18" ry="14" fill={color} />;
    default:
      return <Circle cx="24" cy="24" r="16" fill={color} />;
  }
}